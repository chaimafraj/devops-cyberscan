import os
from pathlib import Path
from datetime import timedelta

from corsheaders.defaults import default_headers
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent


def env_list(name, default=''):
    return [item.strip() for item in config(name, default=default).split(',') if item.strip()]


SECRET_KEY = config('DJANGO_SECRET_KEY', default='django-insecure-development-only-change-me')

DEBUG = config('DEBUG', default=True, cast=bool)

# localhost + testserver (Django test client / APIClient)
ALLOWED_HOSTS = env_list(
    'ALLOWED_HOSTS',
    'localhost,127.0.0.1,[::1],testserver',
)

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'scanner',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('POSTGRES_DB', default='cyberapp_db'),
        'USER': config('POSTGRES_USER', default='postgres'),
        'PASSWORD': config('POSTGRES_PASSWORD', default='postgres'),
        'HOST': config('POSTGRES_HOST', default='127.0.0.1'),
        'PORT': config('POSTGRES_PORT', default=5432, cast=int),
        'OPTIONS': {
            'client_encoding': 'UTF8',
        },
    }
}

AUTH_USER_MODEL = 'scanner.User'  # ← IMPORTANT

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(
        minutes=config('JWT_ACCESS_MINUTES', default=1440, cast=int),
    ),
    'REFRESH_TOKEN_LIFETIME': timedelta(
        days=config('JWT_REFRESH_DAYS', default=7, cast=int),
    ),
    'ROTATE_REFRESH_TOKENS': False,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# --- Médias / rapports PDF CyberScan ---
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'
REPORTS_DIR = MEDIA_ROOT / 'rapports'

# URLs publiques pour les liens dans les emails de rapport
CYBERSCAN_SITE_URL = os.environ.get('CYBERSCAN_SITE_URL', 'http://localhost:4200')
CYBERSCAN_API_URL = os.environ.get('CYBERSCAN_API_URL', 'http://localhost:8000')
CYBERSCAN_HISTORY_URL = os.environ.get(
    'CYBERSCAN_HISTORY_URL',
    f"{CYBERSCAN_SITE_URL.rstrip('/')}/historique",
)
REPORT_EMAIL_LINK_MAX_AGE = int(os.environ.get('REPORT_EMAIL_LINK_MAX_AGE', 7 * 24 * 60 * 60))

# Frontend Angular autorise a appeler l'API Django en developpement.
# Une origine ne contient pas de slash final.
CORS_ALLOW_ALL_ORIGINS = config('CORS_ALLOW_ALL_ORIGINS', default=False, cast=bool)
CORS_ALLOWED_ORIGINS = env_list(
    'CORS_ALLOWED_ORIGINS',
    'http://localhost:4200,http://127.0.0.1:4200',
)

# Necessaire pour les requetes non sures authentifiees par cookie/CSRF.
CSRF_TRUSTED_ORIGINS = env_list(
    'CSRF_TRUSTED_ORIGINS',
    'http://localhost:4200,http://127.0.0.1:4200',
)

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_HEADERS = [
    *default_headers,
    'sec-ch-ua',
    'sec-ch-ua-mobile',
    'sec-ch-ua-platform',
]
CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

# --- Logging : affiche les logs du scanner (dont OWASP ZAP) dans la console ---
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[{asctime}] {levelname} {name}: {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'scanner': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = config(
    'DEFAULT_FROM_EMAIL',
    default=f'CyberScan <{EMAIL_HOST_USER}>' if EMAIL_HOST_USER else 'CyberScan <noreply@localhost>',
)
EMAIL_TIMEOUT = config('EMAIL_TIMEOUT', default=20, cast=int)

# Scanner VM accessed by Paramiko. Keep credentials in the environment rather
# than in source control, and make network timeouts explicit.
SSH_HOST = config('SSH_HOST', default='')
SSH_PORT = config('SSH_PORT', default=22, cast=int)
SSH_USER = config('SSH_USER', default='')
SSH_PASSWORD = config('SSH_PASSWORD', default='')
SSH_CONNECT_TIMEOUT = config('SSH_CONNECT_TIMEOUT', default=15, cast=int)
SSH_COMMAND_TIMEOUT = config('SSH_COMMAND_TIMEOUT', default=60, cast=int)
SSH_AUTO_ADD_HOST_KEY = config('SSH_AUTO_ADD_HOST_KEY', default=False, cast=bool)

# Les scans asynchrones créent les notifications dans le worker Celery.
CELERY_BROKER_URL = config('CELERY_BROKER_URL', default='redis://127.0.0.1:6379/0')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND', default='redis://127.0.0.1:6379/1')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_TRACK_STARTED = True
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
# Sous Windows, le pool prefork bloque ou redemarre les processus enfants.
# Le pool solo garantit l'execution fiable des scans dans le worker dedie.
CELERY_WORKER_POOL = config('CELERY_WORKER_POOL', default='solo')
CELERY_WORKER_CONCURRENCY = config('CELERY_WORKER_CONCURRENCY', default=1, cast=int)
CELERY_TASK_TIME_LIMIT = config('CELERY_TASK_TIME_LIMIT', default=1800, cast=int)
CELERY_TASK_SOFT_TIME_LIMIT = config('CELERY_TASK_SOFT_TIME_LIMIT', default=1740, cast=int)


# Nuclei est volontairement désactivé dans le pipeline et l'interface Scanner.
NUCLEI_ENABLED = False

# Enrichissement réseau utilisé par les rapports (IP, ASN, hébergeur).
IP_METADATA_LOOKUP_ENABLED = config('IP_METADATA_LOOKUP_ENABLED', default=True, cast=bool)
IP_METADATA_URL = config('IP_METADATA_URL', default='https://ipwho.is/{ip}')
IP_METADATA_TIMEOUT = config('IP_METADATA_TIMEOUT', default=8, cast=int)
