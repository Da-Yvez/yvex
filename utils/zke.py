from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64encode, b64decode
import json

class ZKEncryption:
    @staticmethod
    def generate_key(password: str, salt: bytes = None) -> tuple:
        """Generate encryption key from password"""
        if not salt:
            salt = get_random_bytes(16)
        key = PBKDF2(password.encode(), salt, dkLen=32, count=100000)
        return key, salt

    @staticmethod
    def encrypt_file(file_data: bytes, password: str) -> dict:
        """Encrypt file data using ZKE"""
        print(f"Starting encryption of {len(file_data)} bytes")
        
        # Generate master key from password
        master_key, salt = ZKEncryption.generate_key(password)
        
        # Generate random file key - single nonce
        file_key = get_random_bytes(32)
        nonce = get_random_bytes(12)

        # First layer: Encrypt file with file key (using single nonce)
        cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
        encrypted_data, tag = cipher.encrypt_and_digest(file_data)

        # Second layer: Encrypt file key with master key (using same nonce)
        key_cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
        encrypted_file_key, key_tag = key_cipher.encrypt_and_digest(file_key)

        print(f"Encryption complete. Output size: {len(encrypted_data)} bytes")

        return {
            'metadata': {
                'salt': b64encode(salt).decode('utf-8'),
                'nonce': b64encode(nonce).decode('utf-8'),
                'tag': b64encode(tag).decode('utf-8'),
                'key_tag': b64encode(key_tag).decode('utf-8'),
                'encrypted_key': b64encode(encrypted_file_key).decode('utf-8')
            },
            'encrypted_data': encrypted_data
        }

    @staticmethod
    def decrypt_file(encrypted_package: dict, password: str) -> bytes:
        """Decrypt file using ZKE"""
        try:
            print("Starting decryption...")
            metadata = encrypted_package['metadata']
            encrypted_data = encrypted_package['encrypted_data']
            
            print(f"Encrypted data size: {len(encrypted_data)} bytes")
            print(f"Password length: {len(password)}")

            # Reconstruct master key
            salt = b64decode(metadata['salt'])
            print(f"Salt decoded, length: {len(salt)}")
            master_key, _ = ZKEncryption.generate_key(password, salt)
            print("Master key generated")

            # Decrypt file key using master key
            nonce = b64decode(metadata['nonce'])
            print(f"Nonce decoded, length: {len(nonce)}")
            
            key_cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            try:
                file_key = key_cipher.decrypt_and_verify(
                    b64decode(metadata['encrypted_key']),
                    b64decode(metadata['key_tag'])
                )
                print("File key decrypted successfully")
            except ValueError as e:
                print(f"File key decryption failed: {e}")
                raise

            # Decrypt file data using file key
            cipher = AES.new(file_key, AES.MODE_GCM, nonce=nonce)
            try:
                decrypted_data = cipher.decrypt_and_verify(
                    encrypted_data,
                    b64decode(metadata['tag'])
                )
                print(f"File decrypted successfully, size: {len(decrypted_data)} bytes")
                return decrypted_data
            except ValueError as e:
                print(f"File decryption failed: {e}")
                raise

        except Exception as e:
            print(f"Decryption error: {str(e)}")
            raise