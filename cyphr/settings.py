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
import google.cloud.logging
from google.cloud.logging.handlers import CloudLoggingHandler
from .get_secrets_from_gcp import get_secret
import os


class Dev(Configuration):
    # Build paths inside the project like this: BASE_DIR / 'subdir'.
    BASE_DIR = Path(__file__).resolve().parent.parent

    # Quick-start development settings - unsuitable for production
    # See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

    # SECURITY WARNING: keep the secret key used in production secret!
    SECRET_KEY = get_secret(id="django_secret")

    # SECURITY WARNING: don't run with debug turned on in production!
    DEBUG = values.BooleanValue(True)

    ALLOWED_HOSTS = values.ListValue()

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
        "django.middleware.locale.LocaleMiddleware",
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

    LANGUAGES = [
        ("fr", "French"),
        ("en", "English"),
    ]

    LANGUAGE_COOKIE_NAME = "django_language"

    LANGUAGE_COOKIE_PATH = "/"

    TIME_ZONE = values.Value("UTC")

    USE_I18N = True

    USE_L10N = True

    USE_TZ = True

    LOCALE_PATHS = [
        os.path.join(BASE_DIR, "locale"),
    ]

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


# Staging Settings
class Staging(Dev):
    # Debugging is disabled
    DEBUG = False

    # Secret Key
    SECRET_KEY = get_secret(id="django_secret")

    # Static files Root folder
    STATIC_ROOT = "/var/www/cyph3r/static"

    # Media Root folder
    MEDIA_ROOT = "/var/www/cyph3r/media"

    # Set secure proxy header
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

    # Set session cookie age to 8 hours
    SESSION_COOKIE_AGE = 28800

    # Redirect all HTTP requests to HTTPS
    SECURE_SSL_REDIRECT = True

    # Set secure fags for cookies
    SESSION_COOKIE_SECURE = True

    # Set cookie to HttpOnly
    SESSION_COOKIE_HTTPONLY = True

    # Set samesite attribute for cookies
    SESSION_COOKIE_SAMESITE = "Strict"

    # Set CSRF cookie to secure
    CSRF_COOKIE_SECURE = True

    # MIME type sniffing protection
    SECURE_CONTENT_TYPE_NOSNIFF = True

    # Enables Browser XSS filter
    SECURE_BROWSER_XSS_FILTER = True

    # Enables HTTPOnly for CSRF Cookie
    CSRF_COOKIE_HTTPONLY = True

    # Enables HTTPOnly for Language Cookie
    LANGUAGE_COOKIE_HTTPONLY = True

    # Enables Secure for Language Cookie
    LANGUAGE_COOKIE_SECURE = True

    # Enables Samesote for language cookie
    LANGUAGE_COOKIE_SAMESITE = "Strict"

    # Database
    # https://docs.djangoproject.com/en/5.1/ref/settings/#databases

    # DATABASE_PASSWORD = get_secret(id="postgres_secret")

    DATABASES = values.DatabaseURLValue(f"postgres://cyph3r@localhost/cyph3r")

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
        "django.middleware.locale.LocaleMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.middleware.csrf.CsrfViewMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
        "django.middleware.clickjacking.XFrameOptionsMiddleware",
        "django_htmx.middleware.HtmxMiddleware",
    ]

    # Remove Internal IPs
    INTERNAL_IPS = []

    # Logging Settings for Production (to GCP Cloud Logging and to file)
    # Initialize the Cloud Logging client
    client = google.cloud.logging.Client()

    # Set up the handler for sending logs to GCP Cloud Logging
    cloud_logging_handler = CloudLoggingHandler(client)

    LOGGING = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "verbose": {
                "format": "{levelname} {asctime} {module} {message}",
                "style": "{",
            },
        },
        "handlers": {
            "gcp_handler": {
                "level": "DEBUG",
                "class": "google.cloud.logging.handlers.CloudLoggingHandler",
                "client": client,
            },
        },
        "loggers": {
            "": {
                "handlers": ["gcp_handler"],
                "level": "ERROR",
            },
            "django": {
                "handlers": ["gcp_handler"],
                "level": "INFO",
                "propagate": False,
            },
            "django.request": {
                "handlers": ["gcp_handler"],
                "level": "INFO",
                "propagate": False,
            },
            "django.db.backends": {
                "handlers": ["gcp_handler"],
                "level": "ERROR",
                "propagate": False,
            },
        },
    }


# Production Settings
class Prod(Staging):
    pass  # No changes from Staging for now
