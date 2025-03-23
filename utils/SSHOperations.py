import paramiko
import logging
import os
from typing import Tuple

class SSHOperations:
    def __init__(self, host: str, username: str):
        self.host = host
        self.username = username
        self.logger = logging.getLogger(__name__)
        
        # Use service key from config directory
        self.key_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 
            'config', 
            'truenas_service.key'
        )

    def connect(self) -> paramiko.SSHClient:
        """Establish SSH connection using service key"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            self.logger.info(f"Connecting with service key: {self.key_path}")
            ssh.connect(
                self.host, 
                username=self.username,
                key_filename=self.key_path
            )
            return ssh
                
        except Exception as e:
            self.logger.error(f"SSH connection failed: {str(e)}")
            raise

    def execute_command(self, command: str) -> Tuple[bool, str]:
        """Execute a command via SSH"""
        try:
            ssh = self.connect()
            self.logger.info(f"Executing command: {command}")
            
            stdin, stdout, stderr = ssh.exec_command(command)
            error = stderr.read().decode().strip()
            output = stdout.read().decode().strip()

            if error:
                self.logger.error(f"Command failed: {error}")
                return False, error

            return True, output

        except Exception as e:
            self.logger.error(f"Command execution failed: {str(e)}")
            return False, str(e)
        finally:
            if 'ssh' in locals():
                ssh.close()

    def delete_file(self, file_path: str, secure: bool = False) -> Tuple[bool, str]:
        """Delete a file, optionally using secure wipe (Gutmann method)"""
        try:
            if secure:
                # Gutmann method: 35 passes
                command = f"shred -n 35 -u '{file_path}'"  # -n 35 for passes, -u to remove file after
                self.logger.info(f"Secure wiping file using Gutmann method: {file_path}")
            else:
                command = f"rm -f '{file_path}'"
                self.logger.info(f"Standard deletion of file: {file_path}")

            success, output = self.execute_command(command)
            if success:
                return True, "File deleted successfully"
            else:
                return False, f"Failed to delete file: {output}"

        except Exception as e:
            self.logger.error(f"Delete operation failed: {str(e)}")
            return False, str(e)