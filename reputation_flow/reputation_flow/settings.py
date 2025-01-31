"""
Django settings for reputation_flow project.

Generated by 'django-admin startproject' using Django 4.2.16.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""
import os
from pathlib import Path
import json  
from celery.schedules import crontab

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

with open("../config.json","r") as file:
    config = json.load(file)

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config.get('DJANGO_SECURITY_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False
CSRF_TRUSTED_ORIGINS = ['https://tiktok.com']

ALLOWED_HOSTS = ['127.0.0.1','insightlyze.com','www.insightlyze.com']
ALLOWED_HOSTS.append(config.get('SERVER_IP'))
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000  # One year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_REFERRER_POLICY = "no-referrer-when-downgrade"
SECURE_BROWSER_XSS_FILTER = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True

# Application definition
INSTALLED_APPS = [
    'reputation_app',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_user_agents',
    'paypal.standard.ipn',
    'rest_framework',
    'django.contrib.sitemaps',
    'django_celery_results',
    'django_celery_beat'
]

# Celery settings
CELERY_BROKER_URL = 'redis://localhost:6379/0'  # Redis as the message broker
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'

CELERY_RESULT_BACKEND = 'django-db'
CELERY_BEAT_SCHEDULE = {
    'check_scheduled_posts': {
        'task': 'reputation_app.tasks.check_scheduled_posts',  # Path to your task
        'schedule': crontab(minute='*/1'),  # Runs every minute
    },
}
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',  # Adjust the log level as needed (DEBUG, INFO, etc.)
            'class': 'logging.FileHandler',
            'filename': '/home/ubuntu/reputation-flow/celery_beat.log',  # Specify the log file location
        },
    },
    'loggers': {
        'celery.beat': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}


MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django_user_agents.middleware.UserAgentMiddleware',

]
INSTALLED_APPS += ['corsheaders']
MIDDLEWARE.insert(0, 'corsheaders.middleware.CorsMiddleware')
CORS_ALLOW_ALL_ORIGINS = True  
MIDDLEWARE += ['django.middleware.clickjacking.XFrameOptionsMiddleware']

X_FRAME_OPTIONS = 'ALLOWALL'
ROOT_URLCONF = 'reputation_flow.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'reputation_flow.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases
# if DEBUG:
#     DATABASES = {
#         'default': {
#             'ENGINE': 'django.db.backends.sqlite3',
#             'NAME': BASE_DIR / 'db.sqlite3',
#         }
#     }
# else:

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'insightlyze_postgres',  # The name of your database
        'USER': 'hezronbii',  # The PostgreSQL user you created
        'PASSWORD': '@August4th_1998',  # The password for the PostgreSQL user
        'HOST': 'localhost',  # Use 'localhost' if PostgreSQL is on the same server
        'PORT': '5432',  # Default PostgreSQL port
    }
}

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

# AWS S3 Configuration
AWS_ACCESS_KEY_ID = config.get('AWS_S3_ACCESS_KEY')
AWS_SECRET_ACCESS_KEY = config.get('AWS_S3_ACCESS_SECRET')
AWS_STORAGE_BUCKET_NAME = config.get('AWS_STORAGE_BUCKET_NAME')
AWS_S3_REGION_NAME = config.get('AWS_S3_REGION_NAME')
AWS_S3_CUSTOM_DOMAIN = f'{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com'

DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/
AWS_QUERYSTRING_AUTH = False  # Disable query string auth for public URLs

STATIC_URL = 'static/'
LOGIN_URL='/login'

# STATIC_URL = '/static/'  # Already present, defines the URL for static files
STATIC_ROOT = '/home/ubuntu/reputation-flow/reputation_flow/static/'
GEOIP_PATH = '/home/ubuntu/geoip/GeoLite2-City.mmdb'  #

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field
# Media files (uploaded by users)
MEDIA_URL = '/'  # URL prefix for accessing media files
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')  # Absolute path to media directory
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# instagram keys
INSTAGRAM_CLIENT_ID=config.get('INSTAGRAM_CLIENT_ID')
INSTAGRAM_CLIENT_SECRET=config.get('INSTAGRAM_CLIENT_SECRET')
INSTAGRAM_REDIRECT_URI=config.get('INSTAGRAM_REDIRECT_URI')

# facebook keys
FACEBOOK_APP_ID = config.get('FACEBOOK_APP_ID')
FACEBOOK_APP_SECRET = config.get('FACEBOOK_APP_SECRET')
FACEBOOK_REDIRECT_URI = config.get('FACEBOOK_REDIRECT_URI')  

# tiktok
TIKTOK_CLIENT_ID = config.get('TIKTOK_CLIENT_ID')
TIKTOK_CLIENT_SECRET = config.get('TIKTOK_CLIENT_SECRET')
TIKTOK_REDIRECT_URI = config.get('TIKTOK_REDIRECT_URI')  
# TIKTOK_SCOPES = ["video.publish", "user.info.basic", "comment.list"]
TIKTOK_SCOPES = ["user.info.basic"]

# youtube 
YOUTUBE_CLIENT_ID = config.get('YOUTUBE_CLIENT_ID')
YOUTUBE_CLIENT_SECRET = config.get('YOUTUBE_CLIENT_SECRET')
YOUTUBE_REDIRECT_URI = config.get('YOUTUBE_REDIRECT_URI')  
YOUTUBE_SCOPES = ["https://www.googleapis.com/auth/youtube.upload", "https://www.googleapis.com/auth/youtube.force-ssl"]

# google
GOOGLE_CLIENT_ID = config.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = config.get('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = config.get('GOOGLE_REDIRECT_URI')
GOOGLE_SCOPES = ["https://www.googleapis.com/auth/business.manage"]

# reddit
REDDIT_CLIENT_ID = config.get('REDDIT_CLIENT_ID')
REDDIT_CLIENT_SECRET = config.get('REDDIT_CLIENT_SECRET')
REDDIT_REDIRECT_URI = config.get('REDDIT_REDIRECT_URI')
REDDIT_USER_AGENT = config.get('REDDIT_USER_AGENT')

PINECONE_API_KEY = config.get('PINECONE_API_KEY')
PINECONE_ENV = config.get('PINECONE_ENV')
PINECONE_HOST = config.get('PINECONE_HOST')
OPENAI_API_KEY= config.get('OPENAI_API_KEY')

PAYPAL_RECEIVER_EMAIL = config.get('PAYPAL_RECEIVER_EMAIL')
PAYPAL_TEST = True  # Set to False for live transactions
