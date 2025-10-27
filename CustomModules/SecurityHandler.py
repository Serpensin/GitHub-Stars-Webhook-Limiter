"""
Security Handler Module

Provides encryption, decryption, and signature verification utilities
for the GitHub Events Limiter application.

Usage:
    from CustomModules.SecurityHandler import SecurityHandler
    from cryptography.fernet import Fernet

    cipher_suite = Fernet(encryption_key)
    security_handler = SecurityHandler(cipher_suite, logger)

    # Encrypt a secret
    encrypted = security_handler.encrypt_secret("my_secret")

    # Decrypt a secret
    decrypted = security_handler.decrypt_secret(encrypted)

    # Verify a secret
    is_valid = security_handler.verify_secret("my_secret", encrypted)

    # Verify GitHub webhook signature
    is_valid = security_handler.verify_github_signature(
        secret="webhook_secret",
        signature_header="sha256=abc123...",
        payload=request_body_bytes
    )
"""

import hashlib
import hmac
import logging
from typing import Optional


class SecurityHandler:
    """
    Handles encryption, decryption, and cryptographic verification operations.
    """

    def __init__(self, cipher_suite, logger=None):
        """
        Initialize the security handler.

        Args:
            cipher_suite: Fernet cipher suite instance for encryption/decryption
            logger: Logger instance for debug/error logging (optional)
        """
        self.cipher_suite = cipher_suite

        # Initialize logger
        if logger is None:
            self.logger = logging.getLogger("custommodules.securityhandler")
        else:
            self.logger = logger.getChild("custommodules.securityhandler")

    def encrypt_secret(self, secret: str) -> str:
        """
        Encrypts a secret for secure storage.

        Args:
            secret (str): The plaintext secret to encrypt.

        Returns:
            str: The encrypted secret as a base64 string.
        """
        if self.logger:
            self.logger.debug("Encrypting secret")
        return self.cipher_suite.encrypt(secret.encode()).decode()

    def decrypt_secret(self, encrypted_secret: str) -> str:
        """
        Decrypts a stored secret.

        Args:
            encrypted_secret (str): The encrypted secret string.

        Returns:
            str: The decrypted plaintext secret.
        """
        if self.logger:
            self.logger.debug("Decrypting secret")
        return self.cipher_suite.decrypt(encrypted_secret.encode()).decode()

    def verify_secret(self, plaintext_secret: str, encrypted_secret: str) -> bool:
        """
        Verifies a plaintext secret against an encrypted stored secret.

        Args:
            plaintext_secret (str): The plaintext secret to verify.
            encrypted_secret (str): The encrypted secret to compare against.

        Returns:
            bool: True if the secret matches, False otherwise.
        """
        try:
            stored_secret = self.decrypt_secret(encrypted_secret)
            result = hmac.compare_digest(plaintext_secret, stored_secret)
            if self.logger:
                self.logger.debug(f"Secret verification: {'success' if result else 'failed'}")
            return result
        except Exception as e:  # pylint: disable=broad-exception-caught
            if self.logger:
                self.logger.error(f"Secret verification error: {e}")
            return False

    def verify_github_signature(
        self, secret: str, signature_header: Optional[str], payload: bytes
    ) -> bool:
        """
        Validates the GitHub webhook signature using HMAC SHA-256.

        Args:
            secret (str): The webhook secret.
            signature_header (str): The 'x-hub-signature-256' header value.
            payload (bytes): The request body.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        if not signature_header:
            if self.logger:
                self.logger.warning("GitHub signature validation failed: missing signature header")
            return False

        try:
            sha_name, signature = signature_header.split("=", 1)
        except ValueError:
            if self.logger:
                self.logger.warning(
                    "GitHub signature validation failed: malformed signature header"
                )
            return False

        if sha_name != "sha256":
            if self.logger:
                self.logger.warning(
                    f"GitHub signature validation failed: unsupported hash algorithm '{sha_name}'"
                )
            return False

        mac = hmac.new(secret.encode("utf-8"), msg=payload, digestmod=hashlib.sha256)
        expected_signature = mac.hexdigest()
        result = hmac.compare_digest(expected_signature, signature)

        if self.logger:
            if result:
                self.logger.debug("GitHub signature validation successful")
            else:
                self.logger.warning("GitHub signature validation failed: signature mismatch")

        return result
