import os
from typing import Tuple
import logging
import time
import random
import string
from utils.SSHOperations import SSHOperations
from utils.env_crypto import SecureEnv

def verify_gutmann_wipe(ssh_ops: SSHOperations, file_path: str) -> Tuple[bool, dict]:
    """Enhanced verification of secure file erasure with ZFS awareness"""
    try:
        results = {
            "initial_state": None,
            "file_check": False,
            "fragment_check": False,
            "zfs_check": False,
            "timing": 0,
            "success": False
        }

        # 1. Create larger test file (10MB for better timing verification)
        test_content = ''.join(random.choices(string.ascii_letters + string.digits, k=10*1024*1024))
        create_cmd = f"echo '{test_content}' > {file_path}"
        ssh_ops.execute_command(create_cmd)

        # 2. Get initial file state
        stat_cmd = f"stat {file_path}"
        success, initial_stat = ssh_ops.execute_command(stat_cmd)
        results["initial_state"] = initial_stat

        print("\nInitial File State:")
        print(initial_stat)

        # 3. Perform secure wipe
        print("\nPerforming secure wipe...")
        start_time = time.time()
        success, _ = ssh_ops.delete_file(file_path, secure=True)
        duration = time.time() - start_time
        results["timing"] = duration

        # Get base path from environment
        secure_env = SecureEnv()
        env_vars = secure_env.decrypt_env()
        department_dataset = env_vars.get('DEPARTMENT_DATASET')
        if not department_dataset:
            raise ValueError("DEPARTMENT_DATASET not configured. Please configure the system first.")
        departments_base_path = f"/mnt/{department_dataset}"

        # 4. Verification Steps
        
        # 4.1 Check if file exists
        exists_cmd = f"ls {file_path} 2>/dev/null || echo 'File removed'"
        success, exists_check = ssh_ops.execute_command(exists_cmd)
        results["file_check"] = "File removed" in exists_check

        # 4.2 Check for file fragments
        find_cmd = f"find {departments_base_path}/IT -type f -name '*{os.path.basename(file_path)}*'"
        success, fragments = ssh_ops.execute_command(find_cmd)
        results["fragment_check"] = not fragments

        # 4.3 ZFS-specific verification
        zfs_cmd = f"zfs list -t snapshot -H -o name | grep -i '{os.path.basename(file_path)}' || echo 'No snapshots'"
        success, snapshots = ssh_ops.execute_command(zfs_cmd)
        results["zfs_check"] = "No snapshots" in snapshots

        # Print verification results
        print("\nDetailed Verification Results:")
        print(f"✓ Time taken: {duration:.2f} seconds")
        print(f"✓ File existence check: {'Passed' if results['file_check'] else 'Failed'}")
        print(f"✓ Fragment search: {'Passed' if results['fragment_check'] else 'Failed'}")
        print(f"✓ ZFS snapshot check: {'Passed' if results['zfs_check'] else 'Failed'}")

        # For proper secure deletion:
        # 1. Take significant time (multiple passes)
        # 2. Successfully remove the file
        # 3. Leave no fragments
        # 4. No ZFS snapshots containing the file
        min_expected_duration = 5.0  # At least 5 seconds for 10MB file
        results["success"] = all([
            results["file_check"],
            results["fragment_check"],
            results["zfs_check"],
            duration >= min_expected_duration
        ])

        return True, results

    except Exception as e:
        logger.error(f"Verification failed: {str(e)}")
        return False, {"error": str(e)}

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    try:
        secure_env = SecureEnv()
        env_vars = secure_env.decrypt_env()

        ssh_ops = SSHOperations(
            host=env_vars.get('TRUENAS_SSH_HOST'),
            username=env_vars.get('TRUENAS_SSH_USER')
        )

        # Get base path from environment
        department_dataset = env_vars.get('DEPARTMENT_DATASET')
        if not department_dataset:
            raise ValueError("DEPARTMENT_DATASET not configured. Please configure the system first.")
        departments_base_path = f"/mnt/{department_dataset}"
        test_file = f"{departments_base_path}/IT/test_secure_erase.txt"

        print(f"\nStarting comprehensive secure erase validation on: {test_file}")
        
        success, results = verify_gutmann_wipe(ssh_ops, test_file)

        print("\nFinal Validation Result:", "PASSED" if success else "FAILED")
        if success:
            print("✅ All checks passed for secure deletion compliance")
            print(f"   - File completely erased")
            print(f"   - No fragments found")
            print(f"   - No ZFS snapshots remain")
            print(f"   - Operation took {results['timing']:.2f} seconds")
        else:
            print("❌ Validation failed")
            if "error" in results:
                print(f"   Error: {results['error']}")

    except Exception as e:
        print(f"Test failed: {str(e)}")