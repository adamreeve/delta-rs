from abc import ABC, abstractmethod


class KmsClient(ABC):
    """ Abstract base class for KMS clients
    """

    @abstractmethod
    def wrap_key(self, key_bytes: bytes, master_key_identifier: str) -> str:
        """ Encrypt an encryption key
        """
        ...

    @abstractmethod
    def unwrap_key(self, wrapped_key: str, master_key_identifier: str) -> bytes:
        """ Decrypt an encryption key
        """
        ...
