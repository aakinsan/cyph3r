import time
from django.core.management.base import BaseCommand
from django.conf import settings
import os
import shutil


class Command(BaseCommand):
    help = "Delete files and folders in /media older than 4 hours."

    def handle(self, *args, **kwargs):
        now = time.time()

        time_limit = 3 * 60 * 60  # 4 hours in seconds

        for f in os.listdir(settings.MEDIA_ROOT):
            path = os.path.join(settings.MEDIA_ROOT, f)

            # Check last modification time of file or folder has not exceeded time limit
            if now - os.path.getmtime(path) > time_limit:
                try:
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                    self.stdout.write(
                        self.style.SUCCESS(f"Successfully deleted {path}")
                    )
                except Exception as e:
                    self.stderr.write(self.style.ERROR(f"Error deleting {path}: {e}"))
