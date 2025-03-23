// Global variables
let currentStep = 1;

// Utility Functions
function showNotification(title, message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification__message message--${type}`;
    notification.innerHTML = `
        <h1>${title}</h1>
        <p>${message}</p>
        <button aria-label="Dismiss">
            <i class="fas fa-times"></i>
        </button>
    `;

    const container = document.querySelector('.notification') || createNotificationContainer();
    container.appendChild(notification);

    setTimeout(() => notification.classList.add('show'), 10);
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 5000);

    const dismissBtn = notification.querySelector('button');
    dismissBtn.onclick = () => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    };
}

function createNotificationContainer() {
    const container = document.createElement('div');
    container.className = 'notification';
    document.body.appendChild(container);
    return container;
}

function updateProgress(stepNumber) {
    const steps = document.querySelectorAll('.step');
    const stepContents = document.querySelectorAll('.step-content');
    
    steps.forEach(step => {
        const stepNum = parseInt(step.dataset.step);
        if (stepNum < stepNumber) {
            step.classList.add('completed');
            step.classList.remove('active');
        } else if (stepNum === stepNumber) {
            step.classList.add('active');
            step.classList.remove('completed');
        } else {
            step.classList.remove('active', 'completed');
        }
    });

    stepContents.forEach(content => {
        content.classList.add('hidden');
    });
    
    // Show the current step
    document.getElementById(`step${stepNumber}`).classList.remove('hidden');
    
    // Show initial instructions based on step
    const notifications = {
        1: { message: 'Ready to configure YVEX. Please enter your TrueNAS IP address.', type: 'info' },
        2: { message: 'Please enter your TrueNAS API key to continue.', type: 'info' },
        3: { message: 'Enter the dataset path where YVEX will store its data.', type: 'info' },
        4: { message: 'Add the SSH key to your TrueNAS root user for secure access.', type: 'info' },
        5: { message: 'Set up admin and root passwords to secure your YVEX installation.', type: 'info' }
    };
    
    if (notifications[stepNumber]) {
        const notification = document.getElementById(`step${stepNumber}`).querySelector('.notification');
        if (notification) {
            notification.innerHTML = `<i class="fas fa-info-circle"></i> ${notifications[stepNumber].message}`;
            notification.className = `notification ${notifications[stepNumber].type}`;
            notification.style.display = 'block';
        }
    }
}

// Add input validation handlers with enhanced validation
document.getElementById('truenas_ip').addEventListener('input', function() {
    const ip = this.value.trim();
    
    if (!ip) {
        showNotification('Please enter an IP address', 'error', 1);
        return;
    }
    
    if (!isValidIPAddress(ip)) {
        showNotification('Invalid IP format. Example: 192.168.1.100', 'error', 1);
        return;
    }
    
    showNotification('IP address format is valid', 'success', 1);
});

// Step Validation Functions
function validateIP() {
    const ipInput = document.getElementById('truenas_ip');
    const ip = ipInput.value.trim();
    
    if (!ip) {
        showNotification('Please enter an IP address', 'error', 1);
        return;
    }
    
    if (!isValidIPAddress(ip)) {
        showNotification('Invalid IP format. Example: 192.168.1.100', 'error', 1);
        return;
    }
    
    showNotification('Connecting to TrueNAS...', 'success', 1);
    
    fetch('/ping_truenas/' + ip)
    .then(response => response.json())
    .then(data => {
        // Handle Flask messages if present
        if (data.flash_messages && data.flash_messages.length > 0) {
            data.flash_messages.forEach(([category, msg]) => {
                showNotification(msg, category === 'success' ? 'success' : 'error', 1);
            });
        }

        if (data.success) {
            showNotification('✓ Successfully connected to TrueNAS!', 'success', 1);
            setTimeout(() => {
                document.getElementById('step1').classList.add('hidden');
                document.getElementById('step2').classList.remove('hidden');
                updateProgress(2);
            }, 1500);
        } else {
            showNotification(data.message || 'Failed to connect to TrueNAS', 'error', 1);
        }
    })
    .catch(error => {
        showNotification('Error connecting to TrueNAS. Please check if the server is online.', 'error', 1);
    });
}

// Enhanced API key validation
document.getElementById('api_key').addEventListener('input', function() {
    const apiKey = this.value.trim();
    
    if (!apiKey) {
        showNotification('Please enter an API key', 'error', 2);
        return;
    }
    
    if (apiKey.length < 20) {
        showNotification('API key should be at least 20 characters long', 'error', 2);
        return;
    }
    
    showNotification('API key format looks valid', 'success', 2);
});

// Enhanced validateAPIKey function
function validateAPIKey() {
    const apiKeyInput = document.getElementById('api_key');
    const apiKey = apiKeyInput.value.trim();
    
    if (!apiKey) {
        showNotification('Please enter an API key', 'error', 2);
        return;
    }
    
    if (apiKey.length < 20) {
        showNotification('API key should be at least 20 characters long', 'error', 2);
        return;
    }
    
    showNotification('Validating API Key...', 'success', 2);
    
    fetch('/verify_api_key', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
            ip: document.getElementById('truenas_ip').value,
            api_key: apiKey 
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.flash_messages && data.flash_messages.length > 0) {
            data.flash_messages.forEach(([category, msg]) => {
                showNotification(msg, category === 'success' ? 'success' : 'error', 2);
            });
        }

        if (data.success) {
            showNotification('✓ API key validated successfully!', 'success', 2);
            setTimeout(() => {
                document.getElementById('step2').classList.add('hidden');
                document.getElementById('step3').classList.remove('hidden');
                updateProgress(3);
            }, 1500);
        } else {
            showNotification(data.message || 'Invalid API key', 'error', 2);
        }
    })
    .catch(error => {
        showNotification('Error validating API Key. Please try again.', 'error', 2);
    });
}

// Enhanced dataset path validation
document.getElementById('dataset_path').addEventListener('input', function() {
    const path = this.value.trim();
    
    if (!path) {
        showNotification('Please enter a dataset path', 'error', 3);
        return;
    }
    
    if (path.split('/').length < 2) {
        showNotification('Please specify a valid dataset path (e.g., pool/dataset)', 'error', 3);
        return;
    }
    
    showNotification('Dataset path format is valid', 'success', 3);
});

// Enhanced validateDataset function
function validateDataset() {
    const datasetInput = document.getElementById('dataset_path');
    const path = datasetInput.value.trim();
    
    if (!path) {
        showNotification('Please enter a dataset path', 'error', 3);
        return;
    }
    
    showNotification('Checking dataset path...', 'success', 3);
    
    fetch('/check_dataset_path', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
            ip: document.getElementById('truenas_ip').value,
            api_key: document.getElementById('api_key').value,
            path: path
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.flash_messages && data.flash_messages.length > 0) {
            data.flash_messages.forEach(([category, msg]) => {
                showNotification(msg, category === 'success' ? 'success' : 'error', 3);
            });
        }

        if (data.success) {
            showNotification('✓ Dataset found and validated!', 'success', 3);
            setTimeout(() => {
                document.getElementById('step3').classList.add('hidden');
                document.getElementById('step4').classList.remove('hidden');
                updateProgress(4);
            }, 1500);
        } else {
            showNotification(data.message || 'Dataset not found', 'error', 3);
        }
    })
    .catch(error => {
        showNotification('Error checking dataset. Please try again.', 'error', 3);
    });
}

// Password validation
function validatePasswords() {
    const adminPass = document.getElementById('admin_password').value;
    const rootPass = document.getElementById('root_password').value;
    
    if (!adminPass || !rootPass) {
        showNotification('Both passwords are required', 'error', 4);
        return false;
    }
    
    if (adminPass === rootPass) {
        showNotification('Admin and Root passwords must be different', 'error', 4);
        return false;
    }
    
    if (adminPass.length < 8 || rootPass.length < 8) {
        showNotification('Passwords must be at least 8 characters long', 'error', 4);
        return false;
    }
    
    showNotification('Passwords validated successfully', 'success', 4);
    return true;
}

// Enhanced SSH Connection Verification
function verifySSHConnection() {
    const truenas_ip = document.getElementById('truenas_ip').value;
    
    if (!truenas_ip) {
        showNotification('TrueNAS IP is required', 'error', 4);
        return;
    }
    
    // Show notification in the correct container
    const notification = document.getElementById('ssh-notification');
    notification.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verifying SSH connection...';
    notification.className = 'notification success';
    notification.style.display = 'block';
    
    fetch('/verify_ssh_connection', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({ truenas_ip: truenas_ip })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            notification.innerHTML = '<i class="fas fa-check-circle"></i> SSH connection verified successfully!';
            notification.className = 'notification success';
            setTimeout(() => {
                document.getElementById('step4').classList.add('hidden');
                document.getElementById('step5').classList.remove('hidden');
                updateProgress(5);
            }, 1500);
        } else {
            notification.innerHTML = '<i class="fas fa-exclamation-circle"></i> ' + (data.message || 'Failed to verify SSH connection');
            notification.className = 'notification error';
        }
    })
    .catch(error => {
        notification.innerHTML = '<i class="fas fa-exclamation-circle"></i> Error verifying SSH connection. Please try again.';
        notification.className = 'notification error';
    });
}

// SSH Key Functions
function loadSSHKey() {
    fetch('/get_ssh_key')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                document.getElementById('sshKeyContent').textContent = data.key;
            } else {
                showNotification('Error', data.message || 'Failed to load SSH key', 'error');
            }
        })
        .catch(error => {
            showNotification('Error', 'Failed to load SSH key', 'error');
            console.error('Error:', error);
        });
}

// Copy SSH Key Function
function copySSHKey() {
    const sshKeyContent = document.getElementById('sshKeyContent');
    const copyButton = document.querySelector('.btn-secondary');
    const originalText = copyButton.innerHTML;
    
    // Create a temporary textarea to copy the text
    const textarea = document.createElement('textarea');
    textarea.value = sshKeyContent.textContent;
    document.body.appendChild(textarea);
    textarea.select();
    
    try {
        document.execCommand('copy');
        copyButton.innerHTML = '<i class="fas fa-check"></i> Copied!';
        copyButton.classList.add('copied');
        
        // Show success notification
        showNotification('SSH key copied to clipboard', 'success', 4);
        
        // Reset button after 2 seconds
        setTimeout(() => {
            copyButton.innerHTML = originalText;
            copyButton.classList.remove('copied');
        }, 2000);
    } catch (err) {
        console.error('Failed to copy text: ', err);
        copyButton.innerHTML = '<i class="fas fa-times"></i> Failed!';
        showNotification('Failed to copy SSH key', 'error', 4);
    }
    
    document.body.removeChild(textarea);
}

// Form Submission
function handleFormSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(this);
    const adminPass = formData.get('admin_password');
    const rootPass = formData.get('root_password');
    
    // Only validate passwords if we're actually submitting
    if (!adminPass || !rootPass) {
        showNotification('Error', 'Both passwords are required', 'danger');
        return;
    }

    showNotification('Info', 'Saving configuration...', 'info');
    
    fetch('/configure_yvex', {
        method: 'POST',
        body: formData,
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Success', 'Configuration completed!', 'success');
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        } else {
            showNotification('Error', data.message || 'Configuration failed', 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error', 'Configuration failed', 'danger');
    });
}

// Enhanced showNotification function to handle both Flask and client-side messages
function showNotification(message, type = 'success', step) {
    const notificationId = {
        1: 'ip-notification',
        2: 'api-notification',
        3: 'dataset-notification',
        4: 'password-notification'
    }[step] || 'notification';
    
    const notification = document.getElementById(notificationId);
    if (!notification) return;

    const icon = type === 'success' ? 
        '<i class="fas fa-check-circle"></i>' : 
        '<i class="fas fa-exclamation-circle"></i>';
        
    notification.innerHTML = icon + message;
    notification.className = 'notification ' + type;
    notification.style.display = 'block';

    // Add shake animation for errors
    if (type === 'error') {
        notification.classList.add('shake');
        setTimeout(() => notification.classList.remove('shake'), 500);
    }

    // Scroll notification into view with offset
    notification.scrollIntoView({ 
        behavior: 'smooth', 
        block: 'center'
    });

    // Add fade-in animation
    notification.style.animation = 'none';
    notification.offsetHeight; // Trigger reflow
    notification.style.animation = 'slideIn 0.3s ease';
}

// IP address validation function
function isValidIPAddress(ip) {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;
    
    const parts = ip.split('.');
    return parts.every(part => {
        const num = parseInt(part, 10);
        return num >= 0 && num <= 255;
    });
}

function copyCode() {
    const codeElement = document.querySelector('.code-block code');
    const copyButton = document.querySelector('.copy-btn');
    const originalText = copyButton.innerHTML;
    
    // Create a temporary textarea to copy the text
    const textarea = document.createElement('textarea');
    textarea.value = codeElement.textContent;
    document.body.appendChild(textarea);
    textarea.select();
    
    try {
        document.execCommand('copy');
        copyButton.innerHTML = '<i class="fas fa-check"></i><span>Copied!</span>';
        copyButton.classList.add('copied', 'copy-animation');
        
        // Reset button after 2 seconds
        setTimeout(() => {
            copyButton.innerHTML = originalText;
            copyButton.classList.remove('copied', 'copy-animation');
        }, 2000);
    } catch (err) {
        console.error('Failed to copy text: ', err);
        copyButton.innerHTML = '<i class="fas fa-times"></i><span>Failed!</span>';
    }
    
    document.body.removeChild(textarea);
}



// Initialize
document.addEventListener('DOMContentLoaded', function() {
    // Initialize first step with notification
    updateProgress(currentStep);
    showNotification('Info', 'Ready to configure YVEX. Please enter your TrueNAS IP address.', 'info');

    // Form submission handler
    const configForm = document.getElementById('configForm');
    if (configForm) {
        configForm.addEventListener('submit', handleFormSubmit);
    }

    // Copy command functionality
    const copyCommandBtn = document.getElementById('copyCommand');
    if (copyCommandBtn) {
        copyCommandBtn.addEventListener('click', function() {
            const code = document.querySelector('code').innerText;
            navigator.clipboard.writeText(code);
            showNotification('Success', 'Command copied to clipboard!', 'success');
        });
    }

    // Check unlock status
    const lockedContent = document.getElementById('locked-content');
    if (lockedContent && !lockedContent.classList.contains('hidden')) {
        const checkUnlockStatus = setInterval(() => {
            fetch('/check_unlock_status')
                .then(response => response.json())
                .then(data => {
                    if (data.unlocked) {
                        lockedContent.classList.add('hidden');
                        document.getElementById('config-content').classList.remove('hidden');
                        clearInterval(checkUnlockStatus);
                    }
                })
                .catch(error => {
                    console.error('Error checking unlock status:', error);
                });
        }, 5000);
    }

    // Regular unlock status check
    setInterval(() => {
        fetch('/check_unlock_status')
            .then(response => response.json())
            .then(data => {
                if (data.unlocked) {
                    document.getElementById('locked-content').classList.add('hidden');
                    document.getElementById('config-content').classList.remove('hidden');
                }
            })
            .catch(error => console.error('Error checking unlock status:', error));
    }, 5000);

    
});
