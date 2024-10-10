import pytest
from django.urls import reverse
from test_helpers_wireless import (
    validate_post_response,
    validate_response_context,
    process_provider_keys,
    process_milenage_keys,
    process_security_officer_wrap_keys,
    get_wrapped_secret_key,
)


@pytest.mark.django_db
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
def test_wireless_key_generation_milenage_op_keys(
    cleanup_generated_files,
    cm,
    client,
    pgp_public_keys,
    bad_pgp_public_keys,
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
    Test for milenage op keys
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

    # Post/upload bad public keys to the view and validate the response
    bad_response = validate_post_response(
        client,
        generate_keys_url,
        bad_pgp_public_keys,
        pgp_upload_html_page,
        validate_session_data=False,
    )

    assert (
        len(bad_response.context["form"]["security_officers_public_keys"].errors) == 3
    )
    assert len(bad_response.context["form"]["provider_public_keys"].errors) == 3
    assert len(bad_response.context["form"]["milenage_public_key"].errors) == 3

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

    # Process the provider keys
    provider_secret_key = process_provider_keys(cm, response)

    # Process the Milenage keys
    milenage_secret_key = process_milenage_keys(cm, response)

    # Assert the milenage and provider secret keys are the same
    assert milenage_secret_key == provider_secret_key

    # Process the security officer wrap keys
    wrap_key = process_security_officer_wrap_keys(cm, response)

    # Get nonce and wrapped secret key
    nonce, ciphertext = get_wrapped_secret_key(cm, response)

    # Decrypt the wrapped secret key with the wrap key
    decrypted_secret_key = cm.decrypt_with_aes_gcm(wrap_key, nonce, ciphertext)

    # Assert the decrypted secret key is the same as the provider secret key and mileange secret key
    assert (
        decrypted_secret_key
        == cm.hex_to_bytes(provider_secret_key)
        == cm.hex_to_bytes(milenage_secret_key)
    )


@pytest.mark.django_db
def test_wireless_key_generation_milenage_transport_keys(
    cleanup_generated_files,
    cm,
    client,
    pgp_public_keys,
    key_info_milenage_transport_post_data,
    key_gcp_storage_post_data,
    gcp_storage_url,
    pgp_upload_url,
    generate_keys_url,
    gcp_storage_html_page,
    pgp_upload_html_page,
    generate_keys_html_page,
):
    """
    Test for milenage transport keys
    Test that the wireless_gcp_storage_form view renders correctly and validates data.
    Test that the wireless_pgp_upload_form view renders correctly and validates data.
    Test that all session data is stored correctly.
    Test that the secret key is the same for the provider, security officers and the terminal engineer.
    """

    # Post the key information data to the view and validate the response
    validate_post_response(
        client,
        gcp_storage_url,
        key_info_milenage_transport_post_data,
        gcp_storage_html_page,
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

    # Process the provider keys
    provider_secret_key = process_provider_keys(cm, response)

    # Process the Milenage keys
    milenage_secret_key = process_milenage_keys(cm, response)

    # Assert the milenage and provider secret keys are the same
    assert milenage_secret_key == provider_secret_key

    # Process the security officer wrap keys
    wrap_key = process_security_officer_wrap_keys(cm, response)

    # Get nonce and wrapped secret key
    nonce, ciphertext = get_wrapped_secret_key(cm, response)

    # Decrypt the wrapped secret key with the wrap key
    decrypted_secret_key = cm.decrypt_with_aes_gcm(wrap_key, nonce, ciphertext)

    # Assert the decrypted secret key is the same as the provider secret key and mileange secret key
    assert (
        decrypted_secret_key
        == cm.hex_to_bytes(provider_secret_key)
        == cm.hex_to_bytes(milenage_secret_key)
    )


@pytest.mark.django_db
def test_wireless_key_generation_tuak_transport_keys(
    cleanup_generated_files,
    cm,
    client,
    pgp_public_keys,
    key_info_tuak_transport_post_data,
    key_gcp_storage_post_data,
    gcp_storage_url,
    pgp_upload_url,
    generate_keys_url,
    gcp_storage_html_page,
    pgp_upload_html_page,
    generate_keys_html_page,
):
    """
    Test for tuak transport keys
    Test that the wireless_gcp_storage_form view renders correctly and validates data.
    Test that the wireless_pgp_upload_form view renders correctly and validates data.
    Test that all session data is stored correctly.
    Test that the secret key is the same for the provider and the security officers.
    """
    # Post the key information data to the view and validate the response
    validate_post_response(
        client,
        gcp_storage_url,
        key_info_tuak_transport_post_data,
        gcp_storage_html_page,
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

    # Process the provider keys
    provider_secret_key = process_provider_keys(cm, response)

    # Process the security officer wrap keys
    wrap_key = process_security_officer_wrap_keys(cm, response)

    # Get nonce and wrapped secret key
    nonce, ciphertext = get_wrapped_secret_key(cm, response)

    # Decrypt the wrapped secret key with the wrap key
    decrypted_secret_key = cm.decrypt_with_aes_gcm(wrap_key, nonce, ciphertext)

    # Assert the decrypted secret key is the same as the provider secret key
    assert decrypted_secret_key == cm.hex_to_bytes(provider_secret_key)


@pytest.mark.django_db
def test_wireless_key_generation_tuak_op_keys(
    cleanup_generated_files,
    cm,
    client,
    pgp_public_keys,
    key_info_tuak_op_post_data,
    key_gcp_storage_post_data,
    gcp_storage_url,
    pgp_upload_url,
    generate_keys_url,
    gcp_storage_html_page,
    pgp_upload_html_page,
    generate_keys_html_page,
):
    """
    Test for tuak op keys
    Test that the wireless_gcp_storage_form view renders correctly and validates data.
    Test that the wireless_pgp_upload_form view renders correctly and validates data.
    Test that all session data is stored correctly.
    Test that the secret key is the same for the provider and the security officers.
    """
    # Post the key information data to the view and validate the response
    validate_post_response(
        client,
        gcp_storage_url,
        key_info_tuak_op_post_data,
        gcp_storage_html_page,
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

    # Process the provider keys
    provider_secret_key = process_provider_keys(cm, response)

    # Process the security officer wrap keys
    wrap_key = process_security_officer_wrap_keys(cm, response)

    # Get nonce and wrapped secret key
    nonce, ciphertext = get_wrapped_secret_key(cm, response)

    # Decrypt the wrapped secret key with the wrap key
    decrypted_secret_key = cm.decrypt_with_aes_gcm(wrap_key, nonce, ciphertext)

    # Assert the decrypted secret key is the same as the provider secret key
    assert decrypted_secret_key == cm.hex_to_bytes(provider_secret_key)
