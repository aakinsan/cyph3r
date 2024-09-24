from google.cloud import kms_v1
from google.cloud import secretmanager


class GCPManager:
    def __init__(self, project_id: str, kms_keyring_name: str, kms_key_name: str):
        # initialize attributes
        self.project_id = project_id
        self.kms_keyring_name = kms_keyring_name
        self.kms_key_name = kms_key_name
        self.location = "global"

        # Initialize KMS client
        self.kms_client = kms_v1.KeyManagementServiceClient()

        # Initialize Secret Manager client
        self.secret_manager_client = secretmanager.SecretManagerServiceClient()

        # Initialize key-path to kms key.
        self.key_path = self.kms_client.crypto_key_path(
            self.project_id, self.location, self.kms_keyring_name, self.kms_key_name
        )

    def create_secret(self, secret_id: str) -> None:
        """Creates a secret in Secret Manager."""

        # Build parent resource name.
        parent = f"projects/{self.project_id}"

        # Build parent request, initialize arguments and create secret.
        parent_request = {
            "parent": parent,
            "secret_id": secret_id,
            "secret": {"replication": {"automatic": {}}},
        }
        self.secret_manager_client.create_secret(request=parent_request)

    def add_secret_version(self, secret_id: str, payload: bytes) -> None:
        """Add secret version to secrets manager."""

        # Build path to parent.
        parent = self.secret_manager_client.secret_path(self.project_id, secret_id)

        # Add secret version.
        request = {"parent": parent, "payload": {"data": payload}}
        response = self.secret_manager_client.add_secret_version(request=request)

    def get_secret(self, secret_id: str, version_id="latest") -> bytes:
        # Get secret (private key or passphrase) from secrets manager.

        # Build the resource name of the secret version.
        name = f"projects/{self.project_id}/secrets/{secret_id}/versions/{version_id}"

        # Build Request.
        request = {"name": name}

        # Access the secret version.
        response = self.secret_manager_client.access_secret_version(request)

        # Get secret.
        payload = response.payload.data

        # return payload.
        return payload

    def encrypt_secret(self, payload: bytes) -> bytes:
        """Encrypts a secret using Cloud KMS key."""

        # Encrypt payload
        request = {"name": self.key_path, "plaintext": payload}
        response = self.kms_client.encrypt(request=request)

        # Return encrypted secret.
        return response.ciphertext

    def decrypt_secret(self, encrypted_payload: bytes) -> bytes:
        """Decrypts a secret using Cloud KMS key."""

        # Decrypt secret
        request = {"name": self.key_path, "ciphertext": encrypted_payload}
        response = self.kms_client.decrypt(request=request)

        # Return decrypted secret.
        return response.plaintext
