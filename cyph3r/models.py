from django.db import models


class KeyGeneration(models.Model):
    key_id = models.CharField(
        max_length=255, unique=True
    )  # Unique identifier for the key
    algorithm = models.CharField(max_length=50)  # E.g., RSA, AES, Shamir
    key_size = models.IntegerField()  # Key size in bits (e.g., 256, 4096)

    def __str__(self):
        return self.key_id


class KeySplit(models.Model):
    key = models.ForeignKey(
        KeyGeneration, on_delete=models.CASCADE
    )  # Reference to the generated key
    number_of_shares = models.IntegerField()  # Number of shares created

    def __str__(self):
        return f"Split of {self.key.key_id}"


class FileEncryption(models.Model):
    file_id = models.CharField(max_length=255)  # Unique identifier for the file
    encrypted_with_key = models.ForeignKey(
        KeyGeneration, on_delete=models.CASCADE
    )  # Key used for encryption
    encryption_algorithm = models.CharField(max_length=50)  # E.g., AES, RSA

    def __str__(self):
        return self.file_id
