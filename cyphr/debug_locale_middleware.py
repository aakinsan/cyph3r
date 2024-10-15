import logging
from django.utils import translation
from django.middleware.locale import LocaleMiddleware

logger = logging.getLogger(__name__)


class DebugLocaleMiddleware(LocaleMiddleware):
    def process_request(self, request):
        lang_cookie = request.COOKIES.get("django_language")
        logger.info(f"Language cookie from request: {lang_cookie}")
        super().process_request(request)
