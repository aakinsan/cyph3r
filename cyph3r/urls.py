from django.urls import path
from . import views

"""
This module contains the URL patterns for the cyph3r app.

"""

urlpatterns = [
    path("", views.index, name="index"),
    path("wireless/", views.wireless, name="wireless"),
    path("key-share-info/", views.key_share_info, name="key-share-info"),
    path(
        "key-share-reconstruct/",
        views.key_share_reconstruct,
        name="key-share-reconstruct",
    ),
    path(
        "key-share-split/",
        views.key_share_split,
        name="key-share-split",
    ),
    path("key-share-download/", views.key_share_download, name="key-share-download"),
    path("key-share-intro/", views.key_share_intro, name="key-share-intro"),
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
