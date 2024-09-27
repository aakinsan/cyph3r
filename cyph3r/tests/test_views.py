import pytest
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.conf import settings
from cyph3r.crypto import CryptoManager
import os


@pytest.mark.django_db
def test_index_view(client):
    """
    Test that the index view renders correctly.
    """
    url = reverse("index")  # Get the URL for the index view
    response = client.get(url)
    assert response.status_code == 200
    assert "cyph3r/index.html" in [t.name for t in response.templates]


@pytest.mark.django_db
def test_wireless_view(client):
    """
    Test that the wireless view renders correctly.
    """
    url = reverse("wireless")
    response = client.get(url)
    assert response.status_code == 200
    assert "cyph3r/wireless.html" in [t.name for t in response.templates]


@pytest.mark.django_db
def test_wirelesss_key_generation(client):
    """
    Test that the wireless_gcp_storage_form view renders correctly and validates data.
    """
    # Get the URL for the wireless_gcp_storage_form view
    url = reverse("wireless_gcp_storage_form")

    # Create a key information data dictionary for the POST request
    key_info_data = {
        "key_identifier": "test_key_identifier",
        "key_type": "op",
        "protocol": "milenage",
        "key_size": 128,
    }
    # Post the key information data to the view
    response = client.post(url, key_info_data, HTTP_HX_REQUEST="true")

    # Check that the view returns a 200 status code and renders the correct template
    assert response.status_code == 200
    assert "cyph3r/wireless-gcp-storage.html" in [t.name for t in response.templates]

    # Check that the key information data is stored in the session
    assert client.session["key_identifier"] == "test_key_identifier"
    assert client.session["key_type"] == "op"
    assert client.session["protocol"] == "milenage"
    assert client.session["key_size"] == "128"

    # Get the URL for the wireless_pgp_upload_form view
    url = reverse("wireless_pgp_upload_form")

    # Create a key information data dictionary for the POST request
    key_gcp_storage_data = {
        "gcp_project_id": "test_gcp_project_id",
        "gcp_kms_keyring": "",
        "gcp_kms_key": "",
    }

    # Post the gcp storage key details to the view
    response = client.post(url, key_gcp_storage_data, HTTP_HX_REQUEST="true")

    # Check that the view returns a 200 status code and renders the correct template
    assert response.status_code == 200
    assert "cyph3r/wireless-pgp-upload.html" in [t.name for t in response.templates]

    # Check that the key storage data is stored in the session
    assert client.session["gcp_project_id"] == "test_gcp_project_id"
    assert client.session["gcp_kms_keyring"] == ""
    assert client.session["gcp_kms_key"] == ""

    # Get the URL for the wireless_generate_page view
    url = reverse("wireless_generate_keys")

    # Read public keys from disk
    with open(
        "exported_public_keys/so1_1C45D386C0FA1F0E_pubkey.asc", "rb"
    ) as fso1, open(
        "exported_public_keys/so2_1302D17D7AB89284_pubkey.asc", "rb"
    ) as fso2, open(
        "exported_public_keys/so3_8E4DF0BC6678F086_pubkey.asc", "rb"
    ) as fso3, open(
        "exported_public_keys/so4_52BD7A5DBC58679C_pubkey.asc", "rb"
    ) as fso4, open(
        "exported_public_keys/so5_312E10617099212D_pubkey.asc", "rb"
    ) as fso5, open(
        "exported_public_keys/p1_36A7F867D02348E2_pubkey.asc", "rb"
    ) as fp1, open(
        "exported_public_keys/p2_004B67CF5F45143D_pubkey.asc", "rb"
    ) as fp2, open(
        "exported_public_keys/p3_6190B90847840025_pubkey.asc", "rb"
    ) as fp3, open(
        "exported_public_keys/m1_FF18092361401CF1_pubkey.asc", "rb"
    ) as fm1:
        so1 = SimpleUploadedFile("so1_1C45D386C0FA1F0E_pubkey.asc", fso1.read())
        so2 = SimpleUploadedFile("so2_1302D17D7AB89284_pubkey.asc", fso2.read())
        so3 = SimpleUploadedFile("so3_8E4DF0BC6678F086_pubkey.asc", fso3.read())
        so4 = SimpleUploadedFile("so4_52BD7A5DBC58679C_pubkey.asc", fso4.read())
        so5 = SimpleUploadedFile("so5_312E10617099212D_pubkey.asc", fso5.read())
        p1 = SimpleUploadedFile("p1_36A7F867D02348E2_pubkey.asc", fp1.read())
        p2 = SimpleUploadedFile("p2_004B67CF5F45143D_pubkey.asc", fp2.read())
        p3 = SimpleUploadedFile("p3_6190B90847840025_pubkey.asc", fp3.read())
        m1 = SimpleUploadedFile("m1_FF18092361401CF1_pubkey.asc", fm1.read())

    # Create data dictionary for the POST request
    pgp_file_uploads_data = {
        "security_officers_public_keys": [so1, so2, so3, so4, so5],
        "provider_public_keys": [p1, p2, p3],
        "milenage_public_key": m1,
    }

    # Post the public keys to the view
    response = client.post(
        url, pgp_file_uploads_data, HTTP_HX_REQUEST="true", format="multipart"
    )

    # Check that the view returns a 200 status code and renders the correct template
    assert response.status_code == 200
    assert "cyph3r/wireless-generate-keys.html" in [t.name for t in response.templates]

    # Check that context is passed correctly and contains the correct keys
    assert len(response.context["provider_files"]) == 3
    assert len(response.context["security_officer_files"]) == 5
    assert response.context["milenage_file"] is not None

    # Check that files are generated in the media directory
    assert len(os.listdir(settings.MEDIA_ROOT)) == 10

    # Decrypt the provider files
    cm = CryptoManager("pgp_test_keys")

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

    # Reconstrcut the secret key from the provider key shares
    provider_secret_key = cm.bytes_to_hex(
        cm.xor_reconstruct_secret(provider_key_shares)
    )

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

    # check that the decrypted milenage key and provider key are the same
    assert milenage_secret_key == provider_secret_key

    # Initialize list to store security officer key shares
    security_key_shares = []

    for file_name in response.context["security_officer_files"]:
        with open(os.path.join(settings.MEDIA_ROOT, file_name), "rb") as f:
            encrypted_data = f.read()
            decrypted_data = cm.gpg.decrypt(encrypted_data)

            # Check that the decryption was successful
            assert decrypted_data.ok == True

            # Retrieve the security officer shares from the decrypted data
            key_share = str(decrypted_data).split("\n")[7]
            print(key_share)
