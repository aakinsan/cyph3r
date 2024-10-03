from django.conf import settings
import random
import os

"""
Helper functions for testing views.

"""


def validate_post_response(
    client,
    url,
    post_data,
    html_page,
    validate_session_data=True,
):
    """
    Helper function to validate response and client session after posting form data to a view.
    """
    # The wireless views utilize htmx to make POST requests and to swap forms
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
        assert response.context.get("milenage_file") is None
        assert len(os.listdir(settings.MEDIA_ROOT)) == 9


def process_provider_keys(cm, response):
    """
    Helper function to process the provider keys.
    """
    # Initialize list to store provider key shares
    provider_key_shares = []

    for file_name in response.context["provider_files"]:
        with open(os.path.join(settings.MEDIA_ROOT, file_name), "rb") as f:
            provider_encrypted_data = f.read()
            provider_decrypted_data = cm.gpg.decrypt(provider_encrypted_data)

            # Check that the decryption was successful
            assert provider_decrypted_data.ok == True

            # Retrieve the provider key shares from the decrypted data
            provider_key_share = str(provider_decrypted_data).split("\n")[5]

            # Convert to bytes
            provider_key_share_bytes = cm.hex_to_bytes(provider_key_share)

            # Append the provider key share to the list
            provider_key_shares.append(provider_key_share_bytes)

    # Reconstruct the secret key from the provider key shares
    provider_secret_key = cm.bytes_to_hex(
        cm.xor_reconstruct_secret(provider_key_shares)
    )
    # Return secret key
    return provider_secret_key


def process_milenage_keys(cm, response):
    """
    Helper function to process the Milenage keys to be entered at AuC terminal.
    """
    # Retrieve the milenage key to be entered at terminal
    with open(
        os.path.join(settings.MEDIA_ROOT, response.context["milenage_file"]), "rb"
    ) as f:
        milenage_encrypted_data = f.read()
        milenage_decrypted_data = cm.gpg.decrypt(milenage_encrypted_data)

    # Check that the decryption was successful
    assert milenage_decrypted_data.ok == True

    # Retrieve the milenage key from the decrypted data
    milenage_secret_key = str(milenage_decrypted_data)

    # Return secret key
    return milenage_secret_key


def process_security_officer_wrap_keys(cm, response):
    """
    Helper function to process the security officer wrap keys.
    """
    # Initialize list to store security officer key shares
    # This would be stored as a list of tuples - [(key_index, bytes(key_share))]
    security_officers_key_shares = []

    for key_index, file_name in enumerate(
        response.context["security_officer_files"], start=1
    ):
        with open(os.path.join(settings.MEDIA_ROOT, file_name), "rb") as f:
            encrypted_data = f.read()
            decrypted_data = cm.gpg.decrypt(encrypted_data)

            # Check that the decryption was successful
            assert decrypted_data.ok == True

            # Retrieve the security officer shares from the decrypted data
            key_share = str(decrypted_data).split("\n")[7]

            # Convert to bytes
            key_share_bytes = cm.hex_to_bytes(key_share)
            security_officers_key_shares.append((key_index, key_share_bytes))

    # Randomly select 3 shares to reconstruct the wrap key
    random_security_officers_key_shares = random.sample(security_officers_key_shares, 3)

    # Reconstruct the wrap key from the security officer key shares
    wrap_key = cm.shamir_reconstruct_secret(random_security_officers_key_shares)

    # Return wrap key
    return wrap_key


def get_wrapped_secret_key(cm, response):
    """
    Helper function to get the wrapped secret key.
    """
    # Get the wrapped secret key file
    with open(
        os.path.join(settings.MEDIA_ROOT, response.context["wrapped_secret_key_file"]),
        "rb",
    ) as f:
        wrapped_secret_key = f.read().split(b"\n")[-1]

    # Decrypt the wrapped secret key with the wrap key
    # Get nonce from the first 12 bytes of the wrapped secret key
    nonce = cm.hex_to_bytes(wrapped_secret_key.decode("utf-8"))[:12]

    # Get ciphertext from the rest of the wrapped secret key
    ciphertext = cm.hex_to_bytes(wrapped_secret_key.decode("utf-8"))[12:]

    # return nonce and ciphertext
    return nonce, ciphertext
