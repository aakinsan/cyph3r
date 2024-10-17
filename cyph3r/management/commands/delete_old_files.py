import time
from django.core.management.base import BaseCommand
from django.conf import settings
import os
import shutil
import logging

# Define the logger for the module
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Delete files and folders in /media older than 4 hours."

    def handle(self, *args, **kwargs):
        now = time.time()
        if settings.DEBUG:
            media_root = settings.MEDIA_ROOT
        else:
            media_root = os.getenv("MEDIA_ROOT")

        time_limit = 1 * 60 * 60  # 4 hours in seconds

        for f in os.listdir(media_root):
            path = os.path.join(media_root, f)

            # Check last modification time of file or folder has not exceeded time limit
            if now - os.path.getmtime(path) > time_limit:
                try:
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                        logger.info(f"Successfully deleted {path}")
                    else:
                        os.remove(path)
                    logger.info(f"Successfully deleted {path}")
                except Exception as e:
                    logger.error(
                        f"An error occurred in the index view: {e}", exc_info=True
                    )
