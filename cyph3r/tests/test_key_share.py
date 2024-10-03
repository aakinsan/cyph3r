import pytest
from django.urls import reverse
from testing_helpers_keyshare import (
    validate_key_share_info_post_response,
    validate_shamir_key_reconstruction_post_response,
    get_key_share_secret_key_and_validate,
)


def test_key_share_info(client):
    """
    Test that the index view renders correctly.
    """
    url = reverse("key-share-info")  # Get the URL for the index view
    response = client.get(url)
    assert response.status_code == 200
    assert "cyph3r/key_share_templates/key-share-info.html" in [
        t.name for t in response.templates
    ]


@pytest.mark.django_db
def test_key_share_shamir_reconstruction(
    cleanup_generated_files,
    cm,
    client,
    key_share_info_url,
    key_share_reconstruct_url,
    key_share_reconstruct_html_page,
    key_share_download_html_page,
    key_share_info_shamir_reconstruct_post_data,
    key_share_reconstruct_shamir_post_data,
    key_share_reconstruct_shamir_secret_key,
):
    """
    Test that shamir key reconstruction is successful.
    """
    # Post the key information data to the view and validate the response
    validate_key_share_info_post_response(
        client,
        key_share_info_url,
        key_share_info_shamir_reconstruct_post_data,
        key_share_reconstruct_html_page,
    )

    response = validate_shamir_key_reconstruction_post_response(
        client,
        key_share_reconstruct_url,
        key_share_reconstruct_html_page,
        key_share_download_html_page,
        key_share_reconstruct_shamir_post_data,
        key_share_count=3,
    )

    get_key_share_secret_key_and_validate(
        cm, client, response, key_share_reconstruct_shamir_secret_key
    )


@pytest.mark.django_db
def test_key_share_xor_reconstruction(
    cleanup_generated_files,
    cm,
    client,
    key_share_info_url,
    key_share_reconstruct_url,
    key_share_reconstruct_html_page,
    key_share_download_html_page,
    key_share_info_xor_reconstruct_post_data,
    key_share_reconstruct_xor_post_data,
    key_share_reconstruct_xor_secret_key,
):
    """
    Test that xor key reconstruction is successful.
    """
    # Post the key information data to the view and validate the response
    validate_key_share_info_post_response(
        client,
        key_share_info_url,
        key_share_info_xor_reconstruct_post_data,
        key_share_reconstruct_html_page,
    )

    response = validate_shamir_key_reconstruction_post_response(
        client,
        key_share_reconstruct_url,
        key_share_reconstruct_html_page,
        key_share_download_html_page,
        key_share_reconstruct_xor_post_data,
        key_share_count=5,
    )

    get_key_share_secret_key_and_validate(
        cm, client, response, key_share_reconstruct_xor_secret_key
    )
