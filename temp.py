from utils.env_crypto import SecureEnv

# Initialize SecureEnv
secure_env = SecureEnv()

# Get current environment
current_env = secure_env.decrypt_env()

# Update TRUENAS_API_KEY
truenas_api_key = "1-PDU6ZbUvsxgQRDwwySfvwj6Dq2vEOw2MnVHmvuoNw6Xy8cRqHtZ8GNzOtyPkQ9ew"  # Replace with your API key
current_env['TRUENAS_API_KEY'] = truenas_api_key

# Update the environment with the new API key
secure_env.update_env(current_env)

# Print the updated value to verify
print(f"TRUENAS_API_KEY: {current_env.get('TRUENAS_API_KEY', 'Not set')}")