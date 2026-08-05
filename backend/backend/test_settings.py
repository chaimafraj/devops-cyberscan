from .settings import *  # noqa: F401,F403

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

ROOT_URLCONF = 'scanner.test_auth_security'
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
