document.addEventListener('DOMContentLoaded', function () {
    const selectFilesButton = document.getElementById('select-files-button');
    const uploadFilesButton = document.getElementById('upload-files-button');
    const fileInput = document.getElementById('file-input');
    const selectedFileName = document.getElementById('selected-file-name');
    const encryptionPassword = document.getElementById('encryption-password');
    const loadingBar = document.getElementById('loading-bar');
    const progress = loadingBar.querySelector('.progress');
    const fileNameDisplay = loadingBar.querySelector('.file-name');

    // Select files button
    selectFilesButton?.addEventListener('click', () => {
        fileInput.click();
    });

    // Display selected files and show password field
    fileInput?.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            const fileNames = Array.from(fileInput.files).map(file => file.name).join(', ');
            selectedFileName.textContent = `Selected: ${fileNames}`;
            encryptionPassword.style.display = 'inline-block';
            uploadFilesButton.style.display = 'inline-block';
            
            // Show the password notice
            const passwordNotice = document.getElementById('password-notice');
            if (passwordNotice) {
                passwordNotice.style.display = 'flex';
                // Optionally hide the notice after 10 seconds
                setTimeout(() => {
                    passwordNotice.style.display = 'none';
                }, 10000);
            }
        } else {
            selectedFileName.textContent = '';
            encryptionPassword.style.display = 'none';
            uploadFilesButton.style.display = 'none';
            // Hide the password notice
            const passwordNotice = document.getElementById('password-notice');
            if (passwordNotice) {
                passwordNotice.style.display = 'none';
            }
        }
    });

    function uploadFiles(formData) {
        const xhr = new XMLHttpRequest();
        const fileName = Array.from(fileInput.files).map(file => file.name).join(', ');
        const encryptionPassword = document.getElementById('encryption-password').value;

        if (!encryptionPassword) {
            alert('Please enter an encryption password');
            return;
        }

        formData.append('encryption_password', encryptionPassword);
        
        fileNameDisplay.textContent = `Encrypting and uploading: ${fileName}`;
        progress.style.width = '0';
        loadingBar.style.display = 'flex';

        xhr.open('POST', '/upload_file', true);

        xhr.upload.onprogress = function (event) {
            if (event.lengthComputable) {
                const percentComplete = (event.loaded / event.total) * 100;
                progress.style.width = `${percentComplete}%`;
            }
        };

        xhr.onload = function () {
            if (xhr.status === 200) {
                progress.style.width = '100%';
                fileNameDisplay.textContent = 'Upload Complete!';
                setTimeout(() => {
                    loadingBar.style.display = 'none';
                    location.reload();
                }, 1000);
            } else {
                alert(`Upload failed for ${fileName}: ${xhr.responseText}`);
            }
        };

        xhr.onerror = function () {
            alert('Network error during file upload.');
        };

        xhr.send(formData);
    }

    // Rename functionality
    document.querySelectorAll('.rename-file').forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const fileName = this.getAttribute('data-name');
            const originalName = this.getAttribute('data-original-name');
            const modal = document.getElementById('renameModal');
            const form = document.getElementById('renameForm');
            const input = document.getElementById('newFileName');
            const closeBtn = modal.querySelector('.close');
            
            // Set the current original name as value
            input.value = originalName;
            
            // Set the form action
            form.action = `/rename_file/${encodeURIComponent(fileName)}`;
            
            // Show modal with animation
            modal.style.display = 'block';
            // Trigger reflow
            modal.offsetHeight;
            modal.classList.add('show');

            // Close button functionality
            closeBtn.onclick = function() {
                closeModal(modal);
            }

            // Close on outside click
            window.onclick = function(event) {
                if (event.target == modal) {
                    closeModal(modal);
                }
            }
        });
    });

    // Helper function to close modal with animation
    function closeModal(modal) {
        modal.classList.remove('show');
        setTimeout(() => {
            modal.style.display = 'none';
            if (modal.querySelector('form')) {
                modal.querySelector('form').reset();
            }
        }, 300); // Match the animation duration
    }

    // Rename form submission
    document.getElementById('renameForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        const newName = document.getElementById('newFileName').value.trim();
        
        if (!newName) {
            showNotification('Error', 'Please enter a new name', 'danger');
            return;
        }
    
        fetch(this.action, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                'new_name': newName
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification('Success', 'File renamed successfully', 'success');
                // Store notification state in sessionStorage
                sessionStorage.setItem('pendingNotification', JSON.stringify({
                    title: 'Success',
                    message: 'File renamed successfully',
                    type: 'success'
                }));
                // Delay page reload to allow notification to be seen
                setTimeout(() => location.reload(), 3000);
            } else {
                throw new Error(data.error || 'Failed to rename file');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Error', error.message, 'danger');
        });
    
        document.getElementById('renameModal').style.display = 'none';
    });

    // Dropdown menu functionality
    document.querySelectorAll('.dropdown-toggle').forEach(button => {
        button.addEventListener('click', function(e) {
            e.stopPropagation();
            const menu = this.nextElementSibling;
            document.querySelectorAll('.dropdown-menu').forEach(m => {
                if (m !== menu) m.style.display = 'none';
            });
            menu.style.display = menu.style.display === 'block' ? 'none' : 'block';
        });
    });

    // Close dropdowns when clicking outside
    document.addEventListener('click', function() {
        document.querySelectorAll('.dropdown-menu').forEach(menu => {
            menu.style.display = 'none';
        });
    });
});

// Download functionality
function downloadFile(filename) {
    const modal = document.getElementById('downloadModal');
    const form = document.getElementById('downloadForm');
    const closeBtn = modal.querySelector('.close');
    const cancelBtn = modal.querySelector('.cancel-btn');
    const submitBtn = form.querySelector('.confirm-btn');
    const errorMessage = modal.querySelector('.error-message');
    const fileNameElement = modal.querySelector('.file-name');
    const togglePassword = modal.querySelector('.toggle-password');
    const passwordInput = document.getElementById('decryption-password');
    
    // Get original filename from the table row
    const fileRow = document.querySelector(`[onclick*="${filename}"]`).closest('tr');
    const originalFilename = fileRow.querySelector('td').textContent;
    fileNameElement.textContent = originalFilename;
    
    // Reset form and button state
    form.reset();
    submitBtn.disabled = false;
    submitBtn.innerHTML = '<i class="fas fa-download"></i> Download';
    errorMessage.style.display = 'none';
    
    // Show modal with animation
    modal.style.display = 'block';
    modal.offsetHeight; // Trigger reflow
    modal.classList.add('show');
    
    // Password visibility toggle
    togglePassword.addEventListener('click', function() {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        this.classList.toggle('fa-eye');
        this.classList.toggle('fa-eye-slash');
    });
    
    // Close button functionality
    const closeDownloadModal = () => {
        modal.classList.remove('show');
        setTimeout(() => {
            modal.style.display = 'none';
            form.reset();
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="fas fa-download"></i> Download';
            errorMessage.style.display = 'none';
            passwordInput.setAttribute('type', 'password');
            togglePassword.classList.remove('fa-eye');
            togglePassword.classList.add('fa-eye-slash');
        }, 300);
    };

    // Attach close handlers
    closeBtn.onclick = closeDownloadModal;
    cancelBtn.onclick = closeDownloadModal;
    
    // Close on outside click
    window.onclick = function(event) {
        if (event.target == modal) {
            closeDownloadModal();
        }
    }

    form.onsubmit = async function(e) {
        e.preventDefault();
        
        try {
            const password = passwordInput.value;
            
            // Disable button and show loading state
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Downloading...';
            
            const formData = new FormData();
            formData.append('decryption_password', password);
            
            const response = await fetch(`/download_file/${encodeURIComponent(filename)}`, {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fas fa-download"></i> Download';
                
                errorMessage.style.display = 'block';
                errorMessage.textContent = errorData.error || 'Download failed';
                
                setTimeout(() => {
                    errorMessage.style.display = 'none';
                }, 3000);
                
                throw new Error(errorData.error || 'Download failed');
            }
            
            const contentDisposition = response.headers.get('Content-Disposition');
            let downloadFilename = filename;
            if (contentDisposition) {
                const matches = /filename="?([^"]*)"?/.exec(contentDisposition);
                if (matches && matches[1]) {
                    downloadFilename = matches[1];
                }
            }
            
            const blob = await response.blob();
            if (blob.size === 0) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fas fa-download"></i> Download';
                
                errorMessage.style.display = 'block';
                errorMessage.textContent = 'Downloaded file is empty';
                
                setTimeout(() => {
                    errorMessage.style.display = 'none';
                }, 3000);
                
                throw new Error('Downloaded file is empty');
            }
            
            // Create and trigger download
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = downloadFilename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
            
            // Show success notification and close modal
            showNotification('Success', 'File downloaded successfully', 'success');
            closeDownloadModal();
            
        } catch (error) {
            console.error('Download error:', error);
            showNotification('Error', error.message, 'danger');
        }
    };
}

function downloadEncrypted(filename) {
    console.log('Downloading encrypted file:', filename);
    
    fetch(`/download_encrypted/${encodeURIComponent(filename)}`, {
        method: 'GET',
    })
    .then(response => {
        if (!response.ok) throw new Error('Download failed');
        return response.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
    })
    .catch(error => {
        console.error('Download error:', error);
        alert('Failed to download file: ' + error.message);
    });
}

function deleteFile(filename) {
    const modal = document.getElementById('deleteModal');
    const closeBtn = modal.querySelector('.close');
    const cancelBtn = modal.querySelector('.cancel-btn');
    const confirmBtn = modal.querySelector('.confirm-btn');
    const fileNameElement = modal.querySelector('.file-name');
    
    // Get original filename from the table row
    const fileRow = document.querySelector(`[onclick*="${filename}"]`).closest('tr');
    const originalFilename = fileRow.querySelector('td').textContent;
    fileNameElement.textContent = originalFilename;
    
    // Show modal with animation
    modal.style.display = 'block';
    modal.offsetHeight; // Trigger reflow
    modal.classList.add('show');
    
    const closeDeleteModal = () => {
        modal.classList.remove('show');
        setTimeout(() => {
            modal.style.display = 'none';
            confirmBtn.disabled = false;
            confirmBtn.innerHTML = 'Delete';
        }, 300);
    };
    
    // Close button handler
    closeBtn.onclick = closeDeleteModal;
    cancelBtn.onclick = closeDeleteModal;
    
    // Close on outside click
    window.onclick = function(event) {
        if (event.target == modal) {
            closeDeleteModal();
        }
    };
    
    // Confirm button handler
    confirmBtn.onclick = function() {
        // Show loading state
        confirmBtn.disabled = true;
        confirmBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Deleting...';
        
        fetch(`/delete_file/${filename}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showNotification('Error', data.error, 'danger');
            } else {
                showNotification('Success', 'File deleted successfully', 'success');
                setTimeout(() => location.reload(), 1500);
            }
            closeDeleteModal();
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Error', 'Failed to delete file', 'danger');
            closeDeleteModal();
        });
    };
}

function eraseFile(filename) {
    const modal = document.getElementById('eraseModal');
    const closeBtn = modal.querySelector('.close');
    const cancelBtn = modal.querySelector('.cancel-btn');
    const confirmBtn = modal.querySelector('.confirm-btn');
    const fileNameElement = modal.querySelector('.file-name');
    
    // Get original filename from the table row
    const fileRow = document.querySelector(`[onclick*="${filename}"]`).closest('tr');
    const originalFilename = fileRow.querySelector('td').textContent;
    fileNameElement.textContent = originalFilename;
    
    // Show modal with animation
    modal.style.display = 'block';
    modal.offsetHeight; // Trigger reflow
    modal.classList.add('show');
    
    const closeEraseModal = () => {
        modal.classList.remove('show');
        setTimeout(() => {
            modal.style.display = 'none';
            confirmBtn.disabled = false;
            confirmBtn.innerHTML = 'Secure Erase';
        }, 300);
    };
    
    // Close button handler
    closeBtn.onclick = closeEraseModal;
    cancelBtn.onclick = closeEraseModal;
    
    // Close on outside click
    window.onclick = function(event) {
        if (event.target == modal) {
            closeEraseModal();
        }
    };
    
    // Confirm button handler
    confirmBtn.onclick = function() {
        // Show loading state with custom spinner
        confirmBtn.disabled = true;
        confirmBtn.innerHTML = '<i class="fas fa-shield-alt fa-spin"></i> Securely Erasing...';
        
        fetch(`/erase_file/${filename}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showNotification('Error', data.error, 'danger');
            } else {
                showNotification('Success', 'File has been securely erased using the Gutmann method', 'success');
                setTimeout(() => location.reload(), 1500);
            }
            closeEraseModal();
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Error', 'Failed to securely erase file', 'danger');
            closeEraseModal();
        });
    };
}

function toggleAccess(filename) {
    const fileRow = document.querySelector(`[onclick*="${filename}"]`).closest('tr');
    const toggleLink = fileRow.querySelector('[onclick*="toggleAccess"]');
    const icon = toggleLink.querySelector('i');
    const text = toggleLink.querySelector('span') || toggleLink.lastChild;
    
    // Add loading animation
    icon.className = 'fas fa-spinner fa-spin';
    
    fetch(`/toggle_access/${filename}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        credentials: 'same-origin'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        // Update the access status cell
        const statusCell = fileRow.querySelector('td:nth-last-child(2)');
        const statusIcon = statusCell.querySelector('i');
        const statusText = statusCell.querySelector('span');
        
        // Apply transitions
        statusCell.style.transition = 'opacity 0.3s ease';
        statusCell.style.opacity = '0';
        
        setTimeout(() => {
            if (data.is_public) {
                statusIcon.className = 'fas fa-check-circle text-success';
                statusText.textContent = 'Public';
                icon.className = 'fas fa-lock';
                text.textContent = ' Make Private';
            } else {
                statusIcon.className = 'fas fa-times-circle text-danger';
                statusText.textContent = 'Private';
                icon.className = 'fas fa-lock-open';
                text.textContent = ' Make Public';
            }
            
            statusCell.style.opacity = '1';
            
            // Show notification
            showNotification(
                'Access Updated', 
                `File is now ${data.is_public ? 'public' : 'private'}`,
                data.is_public ? 'success' : 'info'
            );
        }, 300);
    })
    .catch(error => {
        console.error('Toggle error:', error);
        icon.className = data.is_public ? 'fas fa-lock' : 'fas fa-lock-open';
        showNotification('Error', 'Failed to change access status', 'danger');
    });
}

function showNotification(title, message, type = 'info') {
    const notification = document.querySelector('.notification');
    const msgElement = notification.querySelector('.notification__message');
    
    // Set content
    msgElement.querySelector('h1').textContent = title;
    msgElement.querySelector('p').textContent = message;
    
    // Set type
    msgElement.className = `notification__message message--${type}`;
    
    // Show notification
    notification.classList.add('received');
    
    // Setup dismiss button
    const dismissBtn = msgElement.querySelector('button');
    dismissBtn.onclick = () => {
        notification.classList.remove('received');
    };
    
    // Auto dismiss after 5 seconds
    setTimeout(() => {
        notification.classList.remove('received');
    }, 5000);
}

// Make downloadFile available globally
window.downloadFile = downloadFile;