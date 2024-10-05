"""
Django settings for cyphr project.

Generated by 'django-admin startproject' using Django 5.1.1.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.1/ref/settings/
"""

from pathlib import Path
from configurations import Configuration, values
import os


class Dev(Configuration):
    # Build paths inside the project like this: BASE_DIR / 'subdir'.
    BASE_DIR = Path(__file__).resolve().parent.parent

    # Quick-start development settings - unsuitable for production
    # See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

    # SECURITY WARNING: keep the secret key used in production secret!
    SECRET_KEY = "django-insecure-xv4lnz$#1#k)lj3a+mz9i6y1n&swfexqfboa&q(%pbj53u#9bv"

    # SECURITY WARNING: don't run with debug turned on in production!
    DEBUG = values.BooleanValue(True)

    ALLOWED_HOSTS = values.ListValue(["192.168.2.121"])

    # Application definition

    INSTALLED_APPS = [
        "django.contrib.admin",
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.sessions",
        "django.contrib.messages",
        "django.contrib.staticfiles",
        "cyph3r",
        "aaa",
        "tailwind",
        "theme",
        "django_browser_reload",
        "widget_tweaks",
        "django_htmx",
    ]

    MIDDLEWARE = [
        "django.middleware.security.SecurityMiddleware",
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.middleware.csrf.CsrfViewMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
        "django.middleware.clickjacking.XFrameOptionsMiddleware",
        "django_htmx.middleware.HtmxMiddleware",
        "django_browser_reload.middleware.BrowserReloadMiddleware",
    ]

    ROOT_URLCONF = "cyphr.urls"

    AUTH_USER_MODEL = "aaa.User"

    TEMPLATES = [
        {
            "BACKEND": "django.template.backends.django.DjangoTemplates",
            "DIRS": [],
            "APP_DIRS": True,
            "OPTIONS": {
                "context_processors": [
                    "django.template.context_processors.debug",
                    "django.template.context_processors.request",
                    "django.contrib.auth.context_processors.auth",
                    "django.contrib.messages.context_processors.messages",
                    "django.template.context_processors.media",
                ],
            },
        },
    ]

    WSGI_APPLICATION = "cyphr.wsgi.application"

    # Database
    # https://docs.djangoproject.com/en/5.1/ref/settings/#databases

    DATABASES = values.DatabaseURLValue(
        f"sqlite:///{BASE_DIR}/db.sqlite3", environ_prefix="DJANGO"
    )

    # Password validation
    # https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

    AUTH_PASSWORD_VALIDATORS = [
        {
            "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
        },
        {
            "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        },
        {
            "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
        },
        {
            "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
        },
    ]

    # Internationalization
    # https://docs.djangoproject.com/en/5.1/topics/i18n/

    LANGUAGE_CODE = "en-us"

    TIME_ZONE = values.Value("UTC")

    USE_I18N = True

    USE_TZ = True

    # Static files (CSS, JavaScript, Images)
    # https://docs.djangoproject.com/en/5.1/howto/static-files/

    STATIC_URL = "static/"

    # Default primary key field type
    # https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

    DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

    STATICFILES_STORAGE = (
        "django.contrib.staticfiles.storage.ManifestStaticFilesStorage"
    )

    # Tailwind CSS app name
    TAILWIND_APP_NAME = "theme"

    # Internal IPs that can recive Django Debug
    INTERNAL_IPS = [
        "127.0.0.1",
        "192.168.2.*",
    ]

    # Media Settings
    MEDIA_URL = "/media/"

    MEDIA_ROOT = values.Value(BASE_DIR / "media")

    # Cache Settings
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": "redis://127.0.0.1:6379",
        }
    }

    # Static files Root folder
    STATIC_ROOT = values.Value()


class Prod(Dev):
    # Debugging is disabled in production
    DEBUG = False

    # Secret Key
    SECRET_KEY = values.SecretValue()

    # Installed Apps and Middleware
    INSTALLED_APPS = [
        "django.contrib.admin",
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.sessions",
        "django.contrib.messages",
        "django.contrib.staticfiles",
        "cyph3r",
        "aaa",
        "tailwind",
        "theme",
        "widget_tweaks",
        "django_htmx",
    ]

    MIDDLEWARE = [
        "django.middleware.security.SecurityMiddleware",
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.middleware.csrf.CsrfViewMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
        "django.middleware.clickjacking.XFrameOptionsMiddleware",
        "django_htmx.middleware.HtmxMiddleware",
    ]

    # Remove Internal IPs
    INTERNAL_IPS = []

    LOGGING = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "verbose": {
                "format": "{levelname} {asctime} {module} {message}",
                "style": "{",
            },
            "simple": {
                "format": "{levelname} {message}",
                "style": "{",
            },
        },
        "handlers": {
            "file": {
                "level": "DEBUG",
                "class": "logging.handlers.RotatingFileHandler",
                "filename": "/var/log/django/debug.log",
                "maxBytes": 1024 * 1024 * 5,
                "backupCount": 5,
                "formatter": "verbose",
            },
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "simple",
            },
        },
        "loggers": {
            "django": {
                "handlers": ["file", "console"],
                "level": values.Value("INFO", environ_name="LOGGING"),
                "propagate": True,
            },
            "django.request": {
                "handlers": ["file", "console"],
                "level": values.Value("ERROR", environ_name="REQUEST_LOGGING"),
                "propagate": False,
            },
        },
    }

    """
    # Secure Defaults
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    """
