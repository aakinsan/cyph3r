from django import forms
import magic

"""
This module contains the forms used in the Cyph3r application.

"""


class MultipleFileInput(forms.ClearableFileInput):
    """Widget for multiple file input"""

    allow_multiple_selected = True


class MultipleFileField(forms.FileField):
    """Field for multiple file input"""

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
    # Key Identifier (Optional)
    key_identifier = forms.CharField(
        label="Key Identifier",
        max_length=100,
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
        cleaned_data = super().clean()
        if (
            cleaned_data.get("protocol") == "milenage"
            and cleaned_data.get("key_type") == "op"
            and cleaned_data.get("key_size") == "256"
        ):
            self.add_error(None, "The Milenage protocol only supports 128-bit OP keys.")


class WirelessGCPStorageForm(forms.Form):
    gcp_project_id = forms.CharField(
        label="GCP Project ID",
        max_length=100,
        help_text="Project ID to store secrets and access KMS key",
        required=False,
    )
    gcp_kms_keyring = forms.CharField(
        label="KMS Keyring",
        max_length=100,
        help_text="GCP KMS key ring name",
        required=False,
    )
    gcp_kms_key = forms.CharField(
        label="KMS Key",
        max_length=100,
        help_text="GCP KMS key name",
        required=False,
    )


class WirelessPGPUploadForm(forms.Form):
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
        files = self.cleaned_data.get("security_officers_public_keys")
        if files:
            # Check if 5 files are uploaded
            if len(files) != 5:
                self.add_error(
                    "security_officers_public_keys",
                    "5 PGP public key files must be uploaded.",
                )
            for file in files:
                # Check file size is less than 5KB
                file_size = file.size
                if file_size > 5120:
                    self.add_error(
                        "security_officers_public_keys",
                        f"{file.name} must be less than 5KB.",
                    )
                # Check file type is PGP public key
                file_type = magic.from_buffer(file.read(), mime=False)
                if not file_type.startswith(
                    ("PGP public key block", "OpenPGP Public Key")
                ):
                    self.add_error(
                        "security_officers_public_keys",
                        f"{file.name} is not a PGP public key file.",
                    )
                # Check if the PGP key is ASCII armored
                file.seek(0)
                first_line = file.readline().strip()
                if first_line != b"-----BEGIN PGP PUBLIC KEY BLOCK-----":
                    self.add_error(
                        "security_officers_public_keys",
                        f"{file.name} must be an ASCII armored PGP public key file.",
                    )

        return files

    def clean_provider_public_keys(self):
        files = self.cleaned_data.get("provider_public_keys")
        if files:
            # Check if 3 files are uploaded
            if len(files) != 3:
                self.add_error(
                    "provider_public_keys", "3 PGP public key files must be uploaded."
                )
            for file in files:
                # Check file size is less than 5KB
                file_size = file.size
                if file_size > 5120:
                    self.add_error(
                        "provider_public_keys", f"{file.name} must be less than 5KB."
                    )
                # Check file type is PGP public key
                file_type = magic.from_buffer(file.read(), mime=False)
                if not file_type.startswith(
                    ("PGP public key block", "OpenPGP Public Key")
                ):
                    self.add_error(
                        "provider_public_keys",
                        f"{file.name} is not a PGP public key file.",
                    )
                # Check if the PGP key is ASCII armored
                file.seek(0)
                first_line = file.readline().strip()
                if first_line != b"-----BEGIN PGP PUBLIC KEY BLOCK-----":
                    self.add_error(
                        "provider_public_keys",
                        f"{file.name} must be an ASCII armored PGP public key file.",
                    )

        return files

    def clean_milenage_public_key(self):
        file = self.cleaned_data.get("milenage_public_key")
        if file:
            file_size = file.size
            if file_size > 5120:
                self.add_error(
                    "milenage_public_key", f"{file.name} must be less than 5KB."
                )
            file_type = magic.from_buffer(file.read(), mime=False)
            if not file_type.startswith(("PGP public key block", "OpenPGP Public Key")):
                self.add_error(
                    "milenage_public_key", f"{file.name} must be a PGP public key file"
                )
            file.seek(0)
            first_line = file.readline().strip()
            if first_line != b"-----BEGIN PGP PUBLIC KEY BLOCK-----":
                self.add_error(
                    "milenage_public_key",
                    f"{file.name} must be an ASCII armored PGP public key file.",
                )
        return file


##############################
# Key Share Management Forms #
# ############################


class KeyShareInputForm(forms.Form):
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
        help_text="Minimum of 32 characters for 128 bit keys.",
    )

    def clean_key_share(self):
        # Check if key share is a hexadecimal string
        key_share = self.cleaned_data.get("key_share")
        if not key_share.isalnum():
            self.add_error("key_share", "Key share must be a hexadecimal string.")
        if not len(key_share) % 32 == 0:
            self.add_error(
                "key_share",
                "Key share must be 128 or 256 bits.",
            )
        return key_share


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
        widget=forms.Select(attrs={"_": "on change call checkSelections()"}),
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
        widget=forms.Select(attrs={"_": "on change call checkSelections()"}),
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
        required=False,
        help_text="Minimum number of key shares for key reconstruction.",
    )

    key_share_public_keys = MultipleFileField(
        required=True,
        help_text="Upload PGP Public keys for key/key-share encryption",
    )

    def clean_key_share_public_keys(self):
        files = self.cleaned_data.get("key_share_public_keys")
        if files:
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
                if not file_type.startswith(
                    ("PGP public key block", "OpenPGP Public Key")
                ):
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

        return files
