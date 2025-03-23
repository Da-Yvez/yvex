from cryptography.fernet import Fernet
import base64
import os
import logging

logger = logging.getLogger(__name__)

class SecureEnv:
    def __init__(self, key_file: str = '.env.key'):
        """Initialize SecureEnv with default configuration"""
        self.key_file = key_file
        # Include existing variables in default config
        self.default_config = {
            # Default empty configuration
            'SECRET_KEY': '',
            'TRUENAS_SSH_HOST': '',
            'TRUENAS_SSH_USER': 'root',  # Default to root as it's standard for TrueNAS
            'TRUENAS_SSH_KEY_PATH': 'config/truenas_service.key',
            'TRUENAS_API_KEY': '',
            'ADMIN_PASSWORD': '',
            
            # YVEX configuration variables
            'CONFIGURED_FLAG': '0',
            'TRUENAS_IP': '',
            'DEPARTMENT_DATASET': '',
            'ROOT_PASSWORD': ''
        }
        self.key = self._load_or_generate_key()
        self.fernet = Fernet(self.key)


    def _load_or_generate_key(self) -> bytes:
        """Load existing key or generate new one"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            os.chmod(self.key_file, 0o600)
            return key

    def encrypt_env(self, env_contents: str = None):
        """Encrypt .env file to .env.encrypted"""
        try:
            if env_contents is None:
                if not os.path.exists('.env'):
                    raise FileNotFoundError('.env file not found')
                with open('.env', 'r') as f:
                    env_contents = f.read()

            encrypted_data = self.fernet.encrypt(env_contents.encode())
            
            with open('.env.encrypted', 'wb') as f:
                f.write(encrypted_data)
            
            os.chmod('.env.encrypted', 0o600)
            logger.info("Environment file encrypted successfully")
            return True
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            return False

    def decrypt_env(self) -> dict:
        """Decrypt and return environment variables as dictionary"""
        try:
            if not os.path.exists('.env.encrypted'):
                logger.warning('.env.encrypted file not found, returning empty dict')
                return {}

            with open('.env.encrypted', 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = self.fernet.decrypt(encrypted_data).decode()
            env_vars = {}

            for line in decrypted_data.splitlines():
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()

            return env_vars
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            return {}

    def update_env(self, updates: dict) -> bool:
        """Update specific values in the encrypted .env file"""
        try:
            # Get current env
            current_env = self.decrypt_env()
            
            # Update with new values while preserving existing ones
            current_env.update(updates)
            
            # Convert to env file format
            env_contents = '\n'.join(f'{k}={v}' for k, v in current_env.items())
            
            # Encrypt and save
            success = self.encrypt_env(env_contents)
            
            if success:
                logger.info("Environment file updated successfully")
                return True
            else:
                logger.error("Failed to update environment file")
                return False

        except Exception as e:
            logger.error(f"Error updating env: {str(e)}")
            return False

    def is_configured(self) -> bool:
        """Check if YVEX has been configured"""
        try:
            env_vars = self.decrypt_env()
            return env_vars.get('CONFIGURED_FLAG', '0') == '1'
        except Exception as e:
            logger.error(f"Error checking configuration status: {str(e)}")
            return False

    def initialize_config(self) -> bool:
        """Initialize default configuration if not exists"""
        try:
            current_env = self.decrypt_env()
            if not current_env:
                # For new installation
                return self.update_env(self.default_config)
            else:
                # For existing installation, only add new config variables
                updates = {}
                for key, value in self.default_config.items():
                    if key not in current_env:
                        updates[key] = value
                if updates:
                    current_env.update(updates)
                    return self.update_env(current_env)
            return True
        except Exception as e:
            logger.error(f"Error initializing config: {str(e)}")
            return False

    def get_value(self, key: str, default: str = None) -> str:
        """Get a specific value from the encrypted env file"""
        try:
            env_vars = self.decrypt_env()
            return env_vars.get(key, default)
        except Exception as e:
            logger.error(f"Error getting value for {key}: {str(e)}")
            return default