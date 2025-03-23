from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64decode

class ZKEncryption2:
    @staticmethod
    def generate_key(password: str, salt: bytes) -> tuple:
        key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
        return key, None

    @staticmethod
    def decrypt_file(encrypted_package: dict, password: str) -> bytes:
        try:
            metadata = encrypted_package['metadata']
            encrypted_data = encrypted_package['encrypted_data']
            
            # Reconstruct master key
            salt = b64decode(metadata['salt'])
            master_key, _ = ZKEncryption2.generate_key(password, salt)
            
            # Decrypt file key
            nonce = b64decode(metadata['nonce'])
            key_cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            file_key = key_cipher.decrypt_and_verify(
                b64decode(metadata['encrypted_key']),
                b64decode(metadata['key_tag'])
            )
            
            # Decrypt file data
            cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(
                encrypted_data,
                b64decode(metadata['tag'])
            )
            return decrypted_data
            
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            raise