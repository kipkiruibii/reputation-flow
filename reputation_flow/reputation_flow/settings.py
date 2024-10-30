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
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# with open("../config.json","r") as file:
#     config = json.load(file)

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
# SECRET_KEY = config.get('DJANGO_SECURITY_KEY')
SECRET_KEY = 'django-insecure-y@m3v3ka!wf3o%1=qr2&r4t9p!5f!1w!%-t95xc4vd@)+9e2bm'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['640a-197-237-137-103.ngrok-free.app','127.0.0.1']


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

]

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

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
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


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'
LOGIN_URL='/login'
# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field
# Media files (uploaded by users)
MEDIA_URL = '/'  # URL prefix for accessing media files
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')  # Absolute path to media directory
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# instagram keys
INSTAGRAM_CLIENT_ID=''
INSTAGRAM_CLIENT_SECRET=''
INSTAGRAM_REDIRECT_URI=''

# facebook keys
FACEBOOK_APP_ID = ''
FACEBOOK_APP_SECRET = ''
FACEBOOK_REDIRECT_URI = ''  

# tiktok
TIKTOK_CLIENT_ID = ""
TIKTOK_CLIENT_SECRET = ""
TIKTOK_REDIRECT_URI = ""  # e.g., "https://yourdomain.com/tiktok/callback/"
TIKTOK_SCOPES = ["video.publish", "user.info.basic", "comment.list"]

# twitter.py
TWITTER_CLIENT_ID = ""
TWITTER_CLIENT_SECRET = ""
TWITTER_REDIRECT_URI = ""  # e.g., "https://yourdomain.com/twitter/callback/"

# youtube 
YOUTUBE_CLIENT_ID = "YOUR_CLIENT_ID"
YOUTUBE_CLIENT_SECRET = "YOUR_CLIENT_SECRET"
YOUTUBE_REDIRECT_URI = "YOUR_REDIRECT_URI"  # e.g., "https://yourdomain.com/youtube/callback/"
YOUTUBE_SCOPES = ["https://www.googleapis.com/auth/youtube.upload", "https://www.googleapis.com/auth/youtube.force-ssl"]

# google
# settings.py
GOOGLE_CLIENT_ID = "YOUR_CLIENT_ID"
GOOGLE_CLIENT_SECRET = "YOUR_CLIENT_SECRET"
GOOGLE_REDIRECT_URI = "YOUR_REDIRECT_URI"  # e.g., "https://yourdomain.com/google-business/callback/"
GOOGLE_SCOPES = ["https://www.googleapis.com/auth/business.manage"]
