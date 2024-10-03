import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from cyph3r.crypto import CryptoManager
from django.urls import reverse
from django.conf import settings
import shutil
import random
import os


@pytest.fixture
def cm():
    """
    Fixture to return a CryptoManager instance.
    """
    # Get the path to the test PGP keys
    gnupghome = settings.BASE_DIR / "cyph3r" / "tests" / "pgp_test_keys"
    return CryptoManager(gnupghome)


@pytest.fixture
def key_share_info_shamir_reconstruct_post_data(pgp_public_keys):
    """
    Fixture to return key information data for Shamir Key Reconstruction.
    """
    return {
        "scheme": "shamir",
        "key_task": "reconstruct",
        "threshold_count": 3,
        "key_share_public_keys": [pgp_public_keys["milenage_public_key"]],
    }


@pytest.fixture
def key_share_reconstruct_shamir_key_shares():
    """
    Fixture to return 3 key shares for reconstructing shamir secret (3 of 5 scheme).
    """
    shamir_key_shares = [
        (1, "e0a387b8443b1a859b36b1b713d8a734"),
        (2, "df4b4059f3de64e74cd6021d101accc0"),
        (3, "64bafef0e76c9e9bb06e154e9d32109e"),
        (4, "9c88dbea3eef2b5a799dc66dd1c92b74"),
        (5, "277965432a5dd1268525d13e5ce1f72a"),
    ]
    # randomly select 3 shares
    return random.sample(shamir_key_shares, 3)


@pytest.fixture
def key_share_reconstruct_shamir_secret_key():
    """
    Fixture to return shamir secret.
    """
    return "5b5239115089e0f9678ea6e49ef07b6a"


@pytest.fixture
def key_share_reconstruct_shamir_post_data(key_share_reconstruct_shamir_key_shares):
    """
    Fixture to return key information data for Shamir Key Reconstruction.
    """
    return [
        {"key_index": idx, "key_share": share}
        for idx, share in key_share_reconstruct_shamir_key_shares
    ]


@pytest.fixture
def key_share_info_url():
    """
    Fixture to return the URL for the Key Share Info form.
    """
    return reverse("key-share-info")


@pytest.fixture
def key_share_reconstruct_url():
    """
    Fixture to return the URL for the Key share reconstruct form
    """
    return reverse("key-share-reconstruct")


@pytest.fixture
def key_share_split_url():
    """
    Fixture to return the URL for the Key share split form
    """
    return reverse("key-share-split")


@pytest.fixture
def key_share_reconstruct_html_page():
    """
    Fixture to return the Generating key HTML page.
    """
    return "cyph3r/key_share_templates/key-share-reconstruct.html"


@pytest.fixture
def key_share_download_html_page():
    """
    Fixture to return the Generating key HTML page.
    """
    return "cyph3r/key_share_templates/key-share-download.html"


@pytest.fixture
def key_info_milenage_op_post_data():
    """
    Fixture to return key information data for Milenage OP key generation.
    """
    return {
        "key_identifier": "test_op_key_identifier",
        "key_type": "op",
        "protocol": "milenage",
        "key_size": "128",
    }


@pytest.fixture
def key_info_milenage_transport_post_data():
    """
    Fixture to return key information data for Milenage OP key generation.
    """
    return {
        "key_identifier": "test_op_key_identifier",
        "key_type": "transport",
        "protocol": "milenage",
        "key_size": "128",
    }


@pytest.fixture
def key_info_tuak_transport_post_data():
    """
    Fixture to return key information data for Tuak Transport key generation.
    """
    return {
        "key_identifier": "test_transport_key_identifier",
        "key_type": "transport",
        "protocol": "tuak",
        "key_size": "256",
    }


@pytest.fixture
def key_info_tuak_op_post_data():
    """
    Fixture to return key information data for Tuak Transport key generation.
    """
    return {
        "key_identifier": "test_transport_key_identifier",
        "key_type": "op",
        "protocol": "tuak",
        "key_size": "256",
    }


@pytest.fixture
def key_gcp_storage_post_data():
    """
    Fixture to return GCP information data for testing.
    """
    return {
        "gcp_project_id": "test_gcp_project_id",
        "gcp_kms_keyring": "",
        "gcp_kms_key": "",
    }


@pytest.fixture
def key_gcp_storage_post_data():
    """
    Fixture to return GCP information data for testing.
    """
    return {
        "gcp_project_id": "test_gcp_project_id",
        "gcp_kms_keyring": "",
        "gcp_kms_key": "",
    }


@pytest.fixture
def gcp_storage_url():
    """
    Fixture to return the URL for the GCP storage form.
    """
    return reverse("wireless_gcp_storage_form")


@pytest.fixture
def pgp_upload_url():
    """
    Fixture to return the URL for the PGP upload form.
    """
    return reverse("wireless_pgp_upload_form")


@pytest.fixture
def generate_keys_url():
    """
    Fixture to return the Generating key URL.
    """
    return reverse("wireless_generate_keys")


@pytest.fixture
def gcp_storage_html_page():
    """
    Fixture to return the HTML page for the GCP storage form.
    """
    return "cyph3r/wireless_templates/wireless-gcp-storage.html"


@pytest.fixture
def pgp_upload_html_page():
    """
    Fixture to return the HTML page for the PGP upload form.
    """
    return "cyph3r/wireless_templates/wireless-pgp-upload.html"


@pytest.fixture
def generate_keys_html_page():
    """
    Fixture to return the Generating key HTML page.
    """
    return "cyph3r/wireless_templates/wireless-generate-keys.html"


@pytest.fixture
def cleanup_generated_files():
    """
    Fixture to cleanup generated files or folders.
    """
    yield
    # Cleanup generated files
    for f in os.listdir(settings.MEDIA_ROOT):
        path = os.path.join(settings.MEDIA_ROOT, f)
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(os.path.join(settings.MEDIA_ROOT, f))


@pytest.fixture
def pgp_public_keys():
    """
    Fixture to return PGP public key files for testing.
    """
    test_public_keys_dir = (
        settings.BASE_DIR / "cyph3r" / "tests" / "exported_public_keys"
    )

    # Read public keys from disk
    with open(
        test_public_keys_dir / "so1_1C45D386C0FA1F0E_pubkey.asc", "rb"
    ) as fso1, open(
        test_public_keys_dir / "so2_1302D17D7AB89284_pubkey.asc", "rb"
    ) as fso2, open(
        test_public_keys_dir / "so3_8E4DF0BC6678F086_pubkey.asc", "rb"
    ) as fso3, open(
        test_public_keys_dir / "so4_52BD7A5DBC58679C_pubkey.asc", "rb"
    ) as fso4, open(
        test_public_keys_dir / "so5_312E10617099212D_pubkey.asc", "rb"
    ) as fso5, open(
        test_public_keys_dir / "p1_36A7F867D02348E2_pubkey.asc", "rb"
    ) as fp1, open(
        test_public_keys_dir / "p2_004B67CF5F45143D_pubkey.asc", "rb"
    ) as fp2, open(
        test_public_keys_dir / "p3_6190B90847840025_pubkey.asc", "rb"
    ) as fp3, open(
        test_public_keys_dir / "m1_FF18092361401CF1_pubkey.asc", "rb"
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

    # Create dictionary for uploaded files
    pgp_file_uploads_data = {
        "security_officers_public_keys": [so1, so2, so3, so4, so5],
        "provider_public_keys": [p1, p2, p3],
        "milenage_public_key": m1,
    }

    return pgp_file_uploads_data
