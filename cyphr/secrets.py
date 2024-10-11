from cyph3r.gcp import GCPManager
import os

"""
Module to get secrets for the cyph3r project.

"""


def get_secret(id=None) -> str:
    """
    Get secret from secrets manager.

    Returns:
        str: Django secret key or PostgreSQL password.
    """
    # Get Project ID from environment variable.
    project_id = os.getenv("GCP_PROJECT_ID")

    # Initialize GCPManager object.
    gcpm = GCPManager(project_id)

    # Get django secret key from secrets manager.
    if id == "django_secret":
        secret_id = os.getenv("DJANGO_SECRET_KEY_SECRET_ID")
        secret = gcpm.get_secret(secret_id).decode("utf-8")

    # Get PostgreSQL password from secrets manager.
    if id == "postgres_secret":
        secret_id = os.getenv("DJANGO_POSTGRES_PASSWORD_SECRET_ID")
        secret = gcpm.get_secret(secret_id).decode("utf-8")

    # Return secret.
    return secret.decode("utf-8")
