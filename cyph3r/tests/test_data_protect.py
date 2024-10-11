from django.test import Client
import pytest
from django.urls import reverse
from cyph3r.crypto import CryptoManager
from test_helpers_dataprotect import (
    validate_data_protect_info_post_response,
)


def test_data_protect_info(
    client: Client,
    data_protect_info_html_page: str,
    data_protect_url: str,
):
    """
    Test that the Data Protect info page view renders correctly.
    """
    response = client.get(data_protect_url)
    assert response.status_code == 200
    assert data_protect_info_html_page in [t.name for t in response.templates]


@pytest.mark.django_db
def test_data_protect_post_response(
    cleanup_generated_files: None,
    cm: CryptoManager,
    client: Client,
    data_protect_url: str,
    data_protect_download_html_page: str,
    data_protect_gcm_encrypt_post_data_pgp: dict,
):
    """
    Post to data protect info view and validate the response
    """
    response = validate_data_protect_info_post_response(
        client,
        data_protect_url,
        data_protect_gcm_encrypt_post_data_pgp,
        data_protect_download_html_page,
    )


@pytest.mark.django_db
def test_key_share_post_long_hex_response(
    cleanup_generated_files: None,
    cm: CryptoManager,
    client: Client,
    data_protect_url: str,
    data_protect_info_html_page: str,
    data_protect_post_long_hex_string: dict,
):
    """
    Test app invalidates keys that are not 128/192/256 bits.
    """
    # Post bad PGP public keys and validate the response
    response = validate_data_protect_info_post_response(
        client,
        data_protect_url,
        data_protect_post_long_hex_string,
        data_protect_info_html_page,
    )
    assert response.context["form"]["aes_key"].errors == [
        "value must be either 128 | 192 | 256 bits."
    ]


@pytest.mark.django_db
def test_key_share_post_bad_hex_response(
    cleanup_generated_files: None,
    cm: CryptoManager,
    client: Client,
    data_protect_url: str,
    data_protect_info_html_page: str,
    data_protect_post_bad_hex_string: dict,
):
    """
    Test app invalidates keys that are non-hexadecimal.
    """
    # Post bad PGP public keys and validate the response
    response = validate_data_protect_info_post_response(
        client,
        data_protect_url,
        data_protect_post_bad_hex_string,
        data_protect_info_html_page,
    )
    assert response.context["form"]["aes_key"].errors == [
        "value must be a hexadecimal string."
    ]
