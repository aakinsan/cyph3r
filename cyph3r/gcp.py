
from google.cloud import kms_v1
from google.cloud import secretmanager

class GCPManager:
    def __init__(self, project_id: str, secret_id: str, keyring_name: str, key_name: str):
        self.project_id = project_id
        self.secret_id = secret_id
        self.keyring_name = keyring_name
        self.key_name = key_name

    def create_secret(self) -> None:
        # Create secret

        # Initialize Secret Manager client.
        client = secretmanager.SecretManagerServiceClient()

        # Build parent resource name.
        parent = f"projects/{self.project_id}"

        # Build parent request, initialize arguments and create secret.
        parent_request = {"parent": parent, "secret_id": self.secret_id, "secret": {"replication": {"automatic": {}}}}
        client.create_secret(request=parent_request)

    def add_secret_version(self, payload: bytes) -> None:
        # Add secret version to secrets manager.

        # Initialize Secret Manager client.
        client = secretmanager.SecretManagerServiceClient()
        
        # Build path to parent.
        parent = client.secret_path(self.project_id, self.secret_id)

        # Add secret version.
        request = {"parent": parent, "payload": {"data": payload}}
        response = client.add_secret_version(request=request)

        # Log Message that secret version has been added.
        gpg_logger.info(f"{response.name} added")

    def get_secret(self, version_id: str) -> bytes:
        # Get secret (private key or passphrase) from secrets manager.

        # Initialize Secret Manager client.
        client = secretmanager.SecretManagerServiceClient()

        # Build the resource name of the secret version.
        name = f"projects/{self.project_id}/secrets/{self.secret_id}/versions/{version_id}"

        # Build Request.
        request = {"name": name}

        # Access the secret version.
        response = client.access_secret_version(request)

        # Get payload.
        payload = response.payload.data

        # Log Message.
        gpg_logger.info(f"{self.secret_id} secret retrieved from GCP Secret Manager")

        # return payload.
        return payload

    def encrypt_passphrase(self, payload: str) -> bytes:
        # Encrypts passphrase.

        # Initialize KMS client.
        client = kms_v1.KeyManagementServiceClient()

        # Build crypto key-path to kms key.
        location="global"
        key_path = client.crypto_key_path(self.project_id, location,
                                          
                                          
                                          
                                          
                                          
                                          
def create_secret(project_id: str, secret_id: str) -> None:
    # Create secret

    # Initialize Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build parent resource name.
    parent = f"projects/{project_id}"

    # Build parent request, initialize arguments and create secret.
    parent_request = {"parent": parent, "secret_id": secret_id, "secret": {"replication": {"automatic": {}}}}
    client.create_secret(request=parent_request)

def add_secret_version(project_id: str, secret_id: str, payload: bytes) -> None:
    # Add secret version to secrets manager.

    # Initialize Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()
    
    # Build path to parent.
    parent = client.secret_path(project_id, secret_id)

    # Add secret version.
    request = {"parent": parent, "payload": {"data": payload}}
    response = client.add_secret_version(request=request)

    # Log Message that secret version has been added.
    gpg_logger.info(f"{response.name} added")



def get_secret(project_id: str, secret_id: str, version_id: str) -> bytes:
    # Get secret (private key or passphrase) from secrets manager.

    # Initialize Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the secret version.
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"

    # Build Request.
    request = {"name": name}

    # Access the secret version.
    response = client.access_secret_version(request)

    # Get payload.
    payload = response.payload.data

    # Log Message.
    gpg_logger.info(f"{secret_id} secret retrieved from GCP Secret Manager")

    # return payload.
    return payload

def encrypt_passphrase(project_id: str, keyring_name: str, key_name: str, payload: str) -> bytes:
    # Encrypts passphrase.

    # Initialize KMS client.
    client = kms_v1.KeyManagementServiceClient()

    # Build crypto key-path to kms key.
    location="global"
    key_path = client.crypto_key_path(project_id, location, keyring_name, key_name)

    # Encrypt payload (passphrase).
    payload_bytes = payload.encode("UTF-8")
    request = {"name": key_path, "plaintext": payload_bytes}
    response = client.encrypt(request=request)

    # Log message.
    gpg_logger.info(f"Passphrase encrypted with Cloud KMS key.")


    # Return encrypted passphrase.
    return response.ciphertext

def decrypt_passphrase(project_id: str, keyring_name: str, key_name: str, encrypted_payload: bytes) -> bytes:
    # Decrypts passphrase.

    # Initialize KMS client.
    client = kms_v1.KeyManagementServiceClient()

# Build crypto key-path.
    location="global"
    key_path = client.crypto_key_path(project_id, location, keyring_name, key_name)

    # Decrypt payload (passphrase).
    request = {"name": key_path, "ciphertext": encrypted_payload}
    response = client.decrypt(request=request)

    # Log Message.
    gpg_logger.info(f"Passphrase decrypted with Cloud KMS key.")
    
    # Return decrypted passphrase.
    return response.plaintext