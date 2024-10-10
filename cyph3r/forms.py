from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
import magic
import re

"""
This module contains the forms used in the Cyph3r application.

"""


class MultipleFileInput(forms.ClearableFileInput):
    """Widget Class for multiple file input"""

    allow_multiple_selected = True


class MultipleFileField(forms.FileField):
    """Field Class for multiple file input"""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("widget", MultipleFileInput())
        super().__init__(*args, **kwargs)

    def clean(self, data, initial=None):
        single_file_clean = super().clean
        if isinstance(data, (list, tuple)):
            result = [single_file_clean(d, initial) for d in data]
        else:
            result = [single_file_clean(data, initial)]
        return result


#################################
# Wireless Key Management Forms #
# ###############################


class WirelessKeyInfoForm(forms.Form):
    """Form for Wireless Key Information"""

    # Key Identifier (Optional)
    key_identifier = forms.CharField(
        label="Key Identifier",
        max_length=15,
        min_length=3,
        required=True,
        help_text="Enter a unique key identifier.",
    )
    # Key Type

    KEY_TYPE_CHOICES = [
        ("transport", "Transport Key"),
        ("op", "Operator (OP) Key"),
    ]

    key_type = forms.ChoiceField(
        choices=KEY_TYPE_CHOICES,
        label="Key Type",
        help_text="Select the key type.",
    )
    # Protocol
    PROTOCOL_TYPE_CHOICES = [
        ("milenage", "Milenage"),
        ("tuak", "Tuak"),
    ]

    protocol = forms.ChoiceField(
        choices=PROTOCOL_TYPE_CHOICES,
        label="Protocol",
        help_text="Select the protocol.",
    )

    # Key Size
    KEY_SIZE_CHOICES = [
        (128, "128-bit"),
        (256, "256-bit"),
    ]

    key_size = forms.ChoiceField(
        choices=KEY_SIZE_CHOICES,
        label="Key Size",
        help_text="Select the key size.",
    )

    def clean(self):
        """Validate the form data to ensure that the key size is valid for the selected protocol"""
        cleaned_data = super().clean()
        if (
            cleaned_data.get("protocol") == "milenage"
            and cleaned_data.get("key_type") == "op"
            and cleaned_data.get("key_size") == "256"
        ):
            self.add_error(None, "The Milenage protocol only supports 128-bit OP keys.")


class WirelessGCPStorageForm(forms.Form):
    """Form for GCP Storage Information"""

    gcp_project_id = forms.CharField(
        label="GCP Project ID",
        max_length=30,
        min_length=6,
        help_text="Project ID to store secrets and access KMS key",
        required=False,
    )
    gcp_kms_keyring = forms.CharField(
        label="KMS Keyring",
        max_length=30,
        min_length=6,
        help_text="GCP KMS key ring name",
        required=False,
    )
    gcp_kms_key = forms.CharField(
        label="KMS Key",
        max_length=30,
        min_length=6,
        help_text="GCP KMS key name",
        required=False,
    )

    def clean_gcp_project_id(self):
        """Validate the GCP Project ID"""
        project_id = self.cleaned_data.get("gcp_project_id")
        if project_id:
            if not re.match(r"\b[a-z][a-z0-9-]*\b", project_id):
                raise ValidationError("Invalid GCP Project ID.")
        return project_id

    def clean_gcp_kms_keyring(self):
        """Validate the GCP KMS Keyring"""
        keyring = self.cleaned_data.get("gcp_kms_keyring")
        if keyring:
            if not re.match(r"\b[a-z][a-z0-9-]*\b", keyring):
                raise ValidationError("Invalid GCP KMS Keyring.")
        return keyring

    def clean_gcp_kms_key(self):
        """Validate the GCP KMS Key"""
        kms_key = self.cleaned_data.get("gcp_kms_key")
        if kms_key:
            if not re.match(r"\b[a-z][a-z0-9-]*\b", kms_key):
                raise ValidationError("Invalid GCP KMS Key.")
        return kms_key


class WirelessPGPUploadForm(forms.Form):
    """Form for PGP Public Key Upload"""

    security_officers_public_keys = MultipleFileField(
        required=True,
        help_text="Upload 5 PGP Public keys for 3 of 5 shamir secret sharing",
    )

    provider_public_keys = MultipleFileField(
        required=True, help_text="Upload 3 Provider PGP Public keys"
    )

    milenage_public_key = forms.FileField(
        required=False, help_text="Upload PGP public key to wrap milenage keys"
    )

    def clean_security_officer_public_keys(self):
        """validate the uploaded security officer public keys files are valid PGP public keys"""
        files = self.cleaned_data.get("security_officers_public_keys")
        self.validate_multiple_files(files, "security_officers_public_keys", 5)
        return files

    def clean_provider_public_keys(self):
        """Validate the uploaded provider public keys files are valid PGP public keys"""
        files = self.cleaned_data.get("provider_public_keys")
        self.validate_multiple_files(files, "provider_public_keys", 3)
        return files

    def clean_milenage_public_key(self):
        file = self.cleaned_data.get("milenage_public_key")
        if file:
            self.validate_single_file(file, "milenage_public_key")
        return file

    def validate_single_file(self, file, field_name):
        # Check file size is less than 5KB
        file_size = file.size
        if file_size > 5120:
            self.add_error(field_name, f"{file.name} must be less than 5KB.")

        # Check file is a PGP public key file
        file_type = magic.from_buffer(file.read(), mime=False)
        if not file_type.startswith(("PGP public key block", "OpenPGP Public Key")):
            self.add_error(field_name, f"{file.name} must be a PGP public key file")

        # Check if the PGP key is ASCII armored
        file.seek(0)
        first_line = file.readline().strip()
        if first_line != b"-----BEGIN PGP PUBLIC KEY BLOCK-----":
            self.add_error(
                field_name,
                f"{file.name} must be an ASCII armored PGP public key file.",
            )

    def validate_multiple_files(self, files, field_name, count):
        # Check if the correct number of files are uploaded
        if len(files) != count:
            self.add_error(
                field_name, f"{count} PGP public key files must be uploaded."
            )
        for file in files:
            self.validate_single_file(file, field_name)


##############################
# Key Share Management Forms #
# ############################


class KeyShareReconstructForm(forms.Form):
    # Key Index for key reconstruction for shamir secret sharing
    key_index = forms.IntegerField(
        label="Key Index", min_value=1, required=False, help_text="Shamir key index."
    )

    # Key Share field for key reconstruction
    key_share = forms.CharField(
        required=True,
        min_length=32,
        max_length=64,
        widget=forms.PasswordInput(),
        label="Key Share (HEXADECIMAL STRING)",
        help_text="Enter 128 bit or 256 key (only xor).",
    )

    def clean_key_share(self):
        # Check if key share is a hexadecimal string and is 128/256 bits (32/64 characters hex)
        key_share = self.cleaned_data.get("key_share")
        if not re.match(r"^[0-9a-fA-F]+$", key_share):
            raise ValidationError("Key share must be a hexadecimal string.")
        if len(key_share) != 32 and len(key_share) != 64:
            raise ValidationError("Key share must be 128 or 256 bits.")
        return key_share


class KeyShareSplitForm(forms.Form):
    # Key Share field for key reconstruction
    key = forms.CharField(
        required=True,
        min_length=32,
        max_length=64,
        widget=forms.PasswordInput(),
        label="Key Share (HEXADECIMAL STRING)",
        help_text="Enter 128 bit or 256 key (only xor).",
    )

    def clean_key_share(self):
        # Check if key share is a hexadecimal string and is 128/256 bits
        key = self.cleaned_data.get("key")
        if not re.match(r"^[0-9a-fA-F]+$", key):
            raise ValidationError("Key share must be a hexadecimal string.")
        if len(key) != 32 and len(key) != 64:
            raise ValidationError("Key share must be 128 or 256 bits.")
        return key


class KeyShareInfoForm(forms.Form):
    # Key Splitting/Reconstruction Options
    KEY_SPLITTING_SCHEMES = [
        ("", "Select a scheme"),
        ("shamir", "Shamir"),
        ("xor", "XOR"),
    ]
    # choice of splitting scheme
    scheme = forms.ChoiceField(
        choices=KEY_SPLITTING_SCHEMES,
        label="Scheme",
        help_text="Select a scheme",
        required=True,
    )

    # XOR Key share choices
    KEY_TASK_CHOICES = [
        ("", "Select a Task"),
        ("split", "Split Key"),
        ("reconstruct", "Reconstruct Key"),
    ]

    key_task = forms.ChoiceField(
        choices=KEY_TASK_CHOICES,
        label="Task",
        help_text="Select a task",
        required=True,
    )

    # Key Share Count (for key splitting, e.g., Shamir Secret Sharing)
    share_count = forms.IntegerField(
        label="Share Count",
        min_value=2,
        max_value=10,
        required=False,
        help_text="Total number of key shares to generate or total number required for key reconstruction (XOR).",
    )

    # Threshold Count (for key splitting, e.g., Shamir Secret Sharing)
    threshold_count = forms.IntegerField(
        label="Threshold Count",
        min_value=2,
        max_value=10,
        required=False,
        help_text="Minimum number of key shares for key reconstruction.",
    )

    key_share_public_keys = MultipleFileField(
        required=True,
        help_text="Upload PGP Public key(s)",
    )

    def clean_key_share_public_keys(self):
        # Get uploaded files
        files = self.cleaned_data.get("key_share_public_keys")
        # Validate uploaded files
        for file in files:
            # Check file size is less than 5KB
            file_size = file.size
            if file_size > 5120:
                self.add_error(
                    "key_share_public_keys",
                    f"{file.name} must be less than 5KB.",
                )
            # Check file type is PGP public key
            file_type = magic.from_buffer(file.read(), mime=False)
            if not file_type.startswith(("PGP public key block", "OpenPGP Public Key")):
                self.add_error(
                    "key_share_public_keys",
                    f"{file.name} is not a PGP public key file.",
                )
            # Check if the PGP key is ASCII armored
            file.seek(0)
            first_line = file.readline().strip()
            if first_line != b"-----BEGIN PGP PUBLIC KEY BLOCK-----":
                self.add_error(
                    "key_share_public_keys",
                    f"{file.name} must be an ASCII armored PGP public key file.",
                )

        # Return files
        return files

    def clean(self):
        # Validate form data based on the selected scheme and key task
        cleaned_data = super().clean()
        scheme = cleaned_data.get("scheme")
        key_task = cleaned_data.get("key_task")
        share_count = cleaned_data.get("share_count")
        threshold_count = cleaned_data.get("threshold_count")
        key_share_public_keys = cleaned_data.get("key_share_public_keys")

        if scheme == "shamir":
            if key_task == "reconstruct":
                if not threshold_count:
                    self.add_error(
                        "threshold_count",
                        "Threshold count is required for Shamir Secret Shares.",
                    )
            elif key_task == "split":
                if not share_count:
                    self.add_error(
                        "share_count",
                        "Share count is required for Shamir Secret Shares.",
                    )
                if not threshold_count:
                    self.add_error(
                        "threshold_count",
                        "Threshold count is required for Shamir Secret Shares.",
                    )
        elif scheme == "xor" and not share_count:
            self.add_error("share_count", "Share count is required for XOR key shares.")

        if key_task == "split" and share_count != len(key_share_public_keys):
            self.add_error(
                None,
                "Total number of public key files must be equal to the share count.",
            )
        if key_task == "reconstruct" and len(key_share_public_keys) != 1:
            self.add_error(
                "key_share_public_keys",
                "Only one PGP Public key file is required for reconstruction.",
            )


#########################
# Data Protection Forms #
# #######################


class DataProtectionForm(forms.Form):
    # AES Mode choices
    AES_MODE_CHOICES = [
        ("", ""),
        ("gcm", "GCM"),
        ("cbc", "CBC"),
    ]
    # choice of AES mode
    aes_mode = forms.ChoiceField(
        choices=AES_MODE_CHOICES,
        label="AES Mode",
        required=True,
    )

    # AES Task choices
    AES_OPERATION_CHOICES = [
        ("", ""),
        ("encrypt", "Encrypt"),
        ("decrypt", "Decrypt"),
    ]

    aes_operation = forms.ChoiceField(
        choices=AES_OPERATION_CHOICES,
        label="AES Operation",
        required=True,
    )

    # Encryption Key
    aes_key = forms.CharField(
        required=True,
        min_length=32,
        max_length=64,
        widget=forms.PasswordInput(),
        label="AES Key",
        help_text="128 | 192 | 256 bit (Hex).",
    )

    # Nonce field for AES GCM decryption
    nonce = forms.CharField(
        label="Nonce",
        max_length=24,
        min_length=24,
        help_text="12 bytes Nonce (Hex)",
        required=False,
    )

    iv = forms.CharField(
        label="IV",
        max_length=32,
        min_length=32,
        help_text="16 bytes IV (Hex)",
        required=False,
    )

    # Associated Data for AES GCM encryption/decryption
    aad = forms.CharField(
        label="ADDITIONAL AUTHENTICATED DATA (AAD)",
        max_length=100,
        required=False,
    )

    # Cipher Text field for AES decryption
    ciphertext = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 2}),
        label="CIPHERTEXT (HEX)",
        required=False,
    )

    # Cipher Text field for AES encryption
    plaintext = forms.CharField(
        widget=forms.Textarea(attrs={"rows": 2}),
        label="Plaintext",
        required=False,
    )

    # PGP public key (Optional)
    public_key = forms.FileField(
        required=False,
        label="PGP Public Key (Optional)",
        help_text="Upload PGP Public key to encrypt output",
    )

    def clean_aes_key(self):
        # Check if AES key is a hexadecimal string and is 128/192/256 bits
        aes_key = self.cleaned_data.get("aes_key")
        if not re.match(r"^[0-9a-fA-F]+$", aes_key):
            raise ValidationError("AES key must be a hexadecimal string.")
        if len(aes_key) != 32 and len(aes_key) != 64 and len(aes_key) != 48:
            raise ValidationError("AES key must be 128, 192, or 256 bits.")
        return aes_key

    def clean_iv(self):
        # Check if IV is a hexadecimal string and is 128 bits
        iv = self.cleaned_data.get("iv")
        if iv:
            if not re.match(r"^[0-9a-fA-F]+$", iv):
                raise ValidationError("IV must be a hexadecimal string.")
        return iv

    def clean_nonce(self):
        # Check if nonce is a hexadecimal string and is 96 bits
        nonce = self.cleaned_data.get("nonce")
        if nonce:
            if not re.match(r"^[0-9a-fA-F]+$", nonce):
                raise ValidationError("Nonce must be a hexadecimal string.")
        return nonce

    def clean_ciphertext(self):
        # Check if ciphertext is a hexadecimal string
        ciphertext = self.cleaned_data.get("ciphertext")
        if ciphertext:
            if not re.match(r"^[0-9a-fA-F]+$", ciphertext):
                raise ValidationError("Ciphertext must be a hexadecimal string.")
        return ciphertext

    def clean_public_key(self):
        file = self.cleaned_data.get("public_key")
        if file:
            self.validate_single_file(file, "public_key")
        return file

    def validate_single_file(self, file, field_name):
        # Check file size is less than 5KB
        file_size = file.size
        if file_size > 5120:
            self.add_error(field_name, f"{file.name} must be less than 5KB.")

        # Check file is a PGP public key file
        file_type = magic.from_buffer(file.read(), mime=False)
        if not file_type.startswith(("PGP public key block", "OpenPGP Public Key")):
            self.add_error(field_name, f"{file.name} must be a PGP public key file")

        # Check if the PGP key is ASCII armored
        file.seek(0)
        first_line = file.readline().strip()
        if first_line != b"-----BEGIN PGP PUBLIC KEY BLOCK-----":
            self.add_error(
                field_name,
                f"{file.name} must be an ASCII armored PGP public key file.",
            )
