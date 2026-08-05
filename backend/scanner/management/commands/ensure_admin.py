import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction


class Command(BaseCommand):
    help = 'Create the initial administrator configured through environment variables.'

    @transaction.atomic
    def handle(self, *args, **options):
        username = os.environ.get('INITIAL_ADMIN_USERNAME', '').strip()
        email = os.environ.get('INITIAL_ADMIN_EMAIL', '').strip()
        password = os.environ.get('INITIAL_ADMIN_PASSWORD', '')

        missing = [
            name
            for name, value in (
                ('INITIAL_ADMIN_USERNAME', username),
                ('INITIAL_ADMIN_EMAIL', email),
                ('INITIAL_ADMIN_PASSWORD', password),
            )
            if not value
        ]
        if missing:
            raise CommandError(
                'Missing required environment variable(s): ' + ', '.join(missing)
            )

        User = get_user_model()
        user = User.objects.select_for_update().filter(username=username).first()

        if user is None:
            if User.objects.filter(email__iexact=email).exists():
                raise CommandError(
                    f'Cannot create initial admin: email {email!r} is already in use.'
                )
            User.objects.create_superuser(
                username=username,
                email=email,
                password=password,
                role='admin',
            )
            self.stdout.write(
                self.style.SUCCESS(f'Initial administrator {username!r} created.')
            )
            return

        conflicting_email = User.objects.filter(email__iexact=email).exclude(pk=user.pk)
        if conflicting_email.exists():
            raise CommandError(
                f'Cannot update initial admin: email {email!r} is already in use.'
            )

        fields_to_update = []
        desired_values = {
            'email': email,
            'role': 'admin',
            'is_staff': True,
            'is_superuser': True,
            'is_active': True,
        }
        for field, value in desired_values.items():
            if getattr(user, field) != value:
                setattr(user, field, value)
                fields_to_update.append(field)

        if fields_to_update:
            user.save(update_fields=fields_to_update)
            self.stdout.write(
                self.style.SUCCESS(f'Initial administrator {username!r} updated.')
            )
        else:
            self.stdout.write(f'Initial administrator {username!r} already exists.')

