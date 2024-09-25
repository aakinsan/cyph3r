from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("wireless/", views.wireless, name="wireless"),
]

htmx_urlpatterns = [
    path(
        "wireless-ceremony-intro/",
        views.wireless_ceremony_intro,
        name="wireless_ceremony_intro",
    ),
    path(
        "wireless-key-info/",
        views.wireless_key_info_form,
        name="wireless_key_info_form",
    ),
    path(
        "wireless-gcp-storage/",
        views.wireless_gcp_storage_form,
        name="wireless_gcp_storage_form",
    ),
    path(
        "wireless-pgp-upload/",
        views.wireless_pgp_upload_form,
        name="wireless_pgp_upload_form",
    ),
    path(
        "wireless-generate-keys/",
        views.wireless_generate_keys,
        name="wireless_generate_keys",
    ),
]

urlpatterns += htmx_urlpatterns
