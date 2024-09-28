import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.conf import settings
import os


@pytest.fixture
def key_info_milenage_op():
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
def key_info_tuak_transport():
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
def key_gcp_storage_data():
    """
    Fixture to return GCP information data for testing.
    """
    return {
        "gcp_project_id": "test_gcp_project_id",
        "gcp_kms_keyring": "",
        "gcp_kms_key": "",
    }


@pytest.fixture
def cleanup_generated_files():
    """
    Fixture to cleanup generated files.
    """
    yield
    # Cleanup generated files
    for file in os.listdir(settings.MEDIA_ROOT):
        os.remove(os.path.join(settings.MEDIA_ROOT, file))


@pytest.fixture(scope="session")
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
