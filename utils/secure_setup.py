import os
import logging

logger = logging.getLogger(__name__)

def set_secure_permissions():
    """Set secure permissions for all sensitive files"""
    try:
        base_dir = os.path.dirname(os.path.dirname(__file__))
        
        # List of sensitive files and their permissions
        sensitive_files = {
            # SSH Keys (most restrictive)
            os.path.join(base_dir, 'config', 'truenas_service.key'): 0o600,
            
            # Config files
            os.path.join(base_dir, '.env'): 0o600,
            os.path.join(base_dir, '.env.key'): 0o600,
            
            # Database file
            os.path.join(base_dir, 'instance', 'users.db'): 0o600,
            
            # Log directory
            os.path.join(base_dir, 'logs'): 0o700,
            
            # Config directory
            os.path.join(base_dir, 'config'): 0o700
        }

        success = True
        for file_path, permission in sensitive_files.items():
            if os.path.exists(file_path):
                os.chmod(file_path, permission)
                logger.info(f"Set {oct(permission)} permissions for: {file_path}")
            else:
                logger.warning(f"File not found: {file_path}")
                success = False

        return success

    except Exception as e:
        logger.error(f"Failed to set secure permissions: {str(e)}")
        return False

def create_secure_directories():
    """Create necessary directories with secure permissions"""
    try:
        base_dir = os.path.dirname(os.path.dirname(__file__))
        
        # List of directories to create
        directories = {
            os.path.join(base_dir, 'config'): 0o700,
            os.path.join(base_dir, 'logs'): 0o700,
            os.path.join(base_dir, 'instance'): 0o700
        }

        for directory, permission in directories.items():
            if not os.path.exists(directory):
                os.makedirs(directory)
            os.chmod(directory, permission)
            logger.info(f"Created/secured directory: {directory}")

        return True

    except Exception as e:
        logger.error(f"Failed to create secure directories: {str(e)}")
        return False