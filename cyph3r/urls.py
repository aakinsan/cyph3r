from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("wireless/", views.wireless, name="wireless"),
]

htmx_urlpatterns = [
    path(
        "wireless-key-protection-storage/",
        views.wireless_key_protection_storage_form,
        name="wireless_key_protection_storage_form",
    ),
    path(
        "wireless-key-info/",
        views.wireless_key_info_form,
        name="wireless_key_info_form",
    ),
    path(
        "wireless-generate-keys/",
        views.wireless_generate_keys,
        name="wireless_generate_keys",
    ),
    path(
        "wireless-ceremony-intro/",
        views.wireless_ceremony_intro,
        name="wireless_ceremony_intro",
    ),
]

urlpatterns += htmx_urlpatterns
