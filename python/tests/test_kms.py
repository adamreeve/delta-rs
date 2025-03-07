import base64
from deltalake.encryption import KmsClient
from deltalake import use_kms_client


class TestKmsClient(KmsClient):
    def wrap_key(self, key_bytes: bytes, master_key_identifier: str) -> str:
        encoded = base64.b64encode(key_bytes).decode('utf-8')
        return f"{master_key_identifier}:{encoded}"

    def unwrap_key(self, wrapped_key: str, master_key_identifier: str) -> bytes:
        master_key_id, b64_key = wrapped_key.split(":", maxsplit=1)
        return base64.b64decode(b64_key)


def test_kms_interaction():
    kms = TestKmsClient()
    result = use_kms_client(kms)
    assert result == "Success"