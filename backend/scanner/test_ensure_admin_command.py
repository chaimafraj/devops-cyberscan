import os
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase


class EnsureAdminCommandTests(TestCase):
    credentials = {
        'INITIAL_ADMIN_USERNAME': 'admin',
        'INITIAL_ADMIN_EMAIL': 'admin@example.com',
        'INITIAL_ADMIN_PASSWORD': 'InitialStrongPassword123!',
    }

    def run_command(self):
        output = StringIO()
        with patch.dict(os.environ, self.credentials, clear=False):
            call_command('ensure_admin', stdout=output)
        return output.getvalue()

    def test_creates_application_and_django_admin(self):
        output = self.run_command()

        user = get_user_model().objects.get(username='admin')
        self.assertEqual(user.email, 'admin@example.com')
        self.assertEqual(user.role, 'admin')
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_active)
        self.assertTrue(user.check_password('InitialStrongPassword123!'))
        self.assertIn('created', output)

    def test_is_idempotent_and_does_not_reset_changed_password(self):
        self.run_command()
        user = get_user_model().objects.get(username='admin')
        user.set_password('AChangedPassword456!')
        user.role = 'viewer'
        user.is_staff = False
        user.is_superuser = False
        user.save()

        output = self.run_command()

        user.refresh_from_db()
        self.assertTrue(user.check_password('AChangedPassword456!'))
        self.assertEqual(user.role, 'admin')
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertIn('updated', output)

    def test_requires_all_credentials(self):
        environment = {
            'INITIAL_ADMIN_USERNAME': 'admin',
            'INITIAL_ADMIN_EMAIL': 'admin@example.com',
            'INITIAL_ADMIN_PASSWORD': '',
        }
        with patch.dict(os.environ, environment, clear=False):
            with self.assertRaisesMessage(CommandError, 'INITIAL_ADMIN_PASSWORD'):
                call_command('ensure_admin')

