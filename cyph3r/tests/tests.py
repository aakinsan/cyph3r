import pytest
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.conf import settings
from cyph3r.crypto import CryptoManager
import random
import os


def test_index_view(client):
    """
    Test that the index view renders correctly.
    """
    url = reverse("index")  # Get the URL for the index view
    response = client.get(url)
    assert response.status_code == 200
    assert "cyph3r/index.html" in [t.name for t in response.templates]


def test_wireless_view(client):
    """
    Test that the wireless intro view renders correctly.
    """
    url = reverse("wireless")
    response = client.get(url)
    assert response.status_code == 200
    assert "cyph3r/wireless.html" in [t.name for t in response.templates]


@pytest.mark.django_db
def test_wireless_key_generation_op_milenage(
    cleanup_generated_files,
    cm,
    client,
    pgp_public_keys,
    key_info_milenage_op_post_data,
    key_gcp_storage_post_data,
    gcp_storage_url,
    pgp_upload_url,
    generate_keys_url,
    gcp_storage_html_page,
    pgp_upload_html_page,
    generate_keys_html_page,
):
    """
    Test that the wireless_gcp_storage_form view renders correctly and validates data.
    Test that the wireless_pgp_upload_form view renders correctly and validates data.
    Test that all session data is stored correctly.
    Test that the secret key is the same for the provider, security officers and the terminal engineer.
    """
    # Post the key information data to the view and validate the response
    validate_post_response(
        client, gcp_storage_url, key_info_milenage_op_post_data, gcp_storage_html_page
    )
    # Post the GCP storage key details to the view and validate the response
    validate_post_response(
        client, pgp_upload_url, key_gcp_storage_post_data, pgp_upload_html_page
    )
    # Post/upload the public keys to the view and validate the response
    response = validate_post_response(
        client,
        generate_keys_url,
        pgp_public_keys,
        generate_keys_html_page,
        validate_session_data=False,
    )
    # Check that the response context is passed correctly
    validate_response_context(client, response)


def validate_post_response(
    client, url, post_data, html_page, validate_session_data=True
):
    """
    Helper function to validate response and client session after posting form data to a view.
    """
    response = client.post(url, post_data, HTTP_HX_REQUEST="true", format="multipart")
    assert response.status_code == 200
    assert html_page in [t.name for t in response.templates]
    if validate_session_data:
        for key, value in post_data.items():
            assert client.session[key] == value
    return response


def validate_response_context(client, response):
    """
    Helper function to validate the context of a response.
    """
    assert len(response.context["provider_files"]) == 3
    assert len(response.context["security_officer_files"]) == 5
    assert response.context["wrapped_secret_key_file"] is not None
    if client.session["protocol"] == "milenage":
        assert response.context["milenage_file"] is not None
        assert len(os.listdir(settings.MEDIA_ROOT)) == 10
    else:
        assert response.context["milenage_file"] is None
        assert len(os.listdir(settings.MEDIA_ROOT)) == 9


def process_provider_keys(cm, response):
    """
    Helper function to process the provider keys.
    """
