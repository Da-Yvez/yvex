document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('departmentSettingsModal');
    const closeBtn = modal.querySelector('.close');
    const updateForm = document.getElementById('updateDepartmentForm');
    const settingsOptions = document.getElementById('settingsOptions');
    const updateSettingsForm = document.getElementById('updateSettingsForm');
    const updateSettingsBtn = document.getElementById('updateSettingsBtn');
    const backBtn = modal.querySelector('.btn-back');

    // Delete department elements
    const deleteBtn = document.querySelector('.settings-btn[data-action="delete"]');
    const deleteModal = document.getElementById('deleteDepartmentModal');
    const deleteForm = document.getElementById('deleteDepartmentForm');
    const closeDeleteModal = deleteModal.querySelector('.close');
    const cancelDeleteBtn = deleteModal.querySelector('.btn-cancel');

    const logsBtn = document.querySelector('.settings-btn[data-action="logs"]');
    const logsModal = document.getElementById('departmentLogsModal');
    const closeLogsModal = logsModal.querySelector('.close');

    // Auto-dismiss success notifications after 5 seconds
    const successMessages = document.querySelectorAll('.flash-message.success');
    successMessages.forEach(message => {
        setTimeout(() => {
            message.style.opacity = '0';
            setTimeout(() => message.remove(), 300);
        }, 5000);
    });

    // Handle settings button click
    window.handleSettings = function() {
        fetch('/check_admin')
            .then(response => response.json())
            .then(data => {
                showModal(data.is_admin);
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('Error', 'Failed to verify admin status', 'error');
            });
    };

    function showModal(isAdmin) {
        modal.style.display = 'block';
        settingsOptions.style.display = 'block';
        updateSettingsForm.style.display = 'none';
        setTimeout(() => modal.classList.add('show'), 50);

        if (!isAdmin) {
            disableButtons();
            showNotification('You must be an admin to use the department settings', 'error');
        }
    }

    function disableButtons() {
        updateSettingsBtn.disabled = true;
        deleteBtn.disabled = true;
        logsBtn.disabled = true;
    }

    function closeModal() {
        modal.classList.remove('show');
        setTimeout(() => {
            modal.style.display = 'none';
            updateForm.reset();
        }, 300);
    }

    // Close modal events
    if (closeBtn) closeBtn.onclick = closeModal;
    window.onclick = function(event) {
        if (event.target == modal) {
            closeModal();
        }
    };

    // Show update settings form when Update Department Settings is clicked
    if (updateSettingsBtn) {
        updateSettingsBtn.addEventListener('click', function() {
            settingsOptions.style.display = 'none';
            updateSettingsForm.style.display = 'block';
        });
    }

    // Handle back button click
    if (backBtn) {
        backBtn.addEventListener('click', function() {
            updateSettingsForm.style.display = 'none';
            settingsOptions.style.display = 'block';
            updateForm.reset();
        });
    }

    // Show delete modal when delete button is clicked
    if (deleteBtn) {
        deleteBtn.addEventListener('click', function() {
            deleteModal.style.display = 'block';
            setTimeout(() => deleteModal.classList.add('show'), 50);
        });
    }

    // Close delete modal
    function closeDeleteModalFunc() {
        deleteModal.classList.remove('show');
        setTimeout(() => {
            deleteModal.style.display = 'none';
            deleteForm.reset();
        }, 300);
    }

    if (closeDeleteModal) closeDeleteModal.onclick = closeDeleteModalFunc;
    if (cancelDeleteBtn) cancelDeleteBtn.onclick = closeDeleteModalFunc;

    // Handle delete form submission
    if (deleteForm) {
        deleteForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);

            fetch('/delete_department', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('Success', data.message, 'success');
                    closeDeleteModalFunc();
                    setTimeout(() => location.reload(), 1500);
                } else {
                    throw new Error(data.message || 'Failed to delete department');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('Error', error.message, 'error');
            });
        });
    }

    // Handle form submission
    if (updateForm) {
        updateForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(updateForm);
        
            fetch('/update_department', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'  // Add this header
                }
            })
            .then(response => {
                if (!response.ok) {
                    if (response.status === 401) {
                        window.location.href = '/login';  // Redirect to login if unauthorized
                        return;
                    }
                    return response.json().then(data => Promise.reject(data));
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    showModalNotification(data.message, 'success');
                    setTimeout(() => {
                        window.location.reload();
                    }, 1500);
                } else {
                    showModalNotification(data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showModalNotification(error.message || 'An error occurred', 'error');
            });
        });
    }

    function showNotification(title, message, type) {
        const existingNotifications = modal.querySelectorAll('.flash-message');
        existingNotifications.forEach(notification => {
            notification.style.opacity = '0';
            setTimeout(() => notification.remove(), 300);
        });
        
        const notification = document.createElement('div');
        notification.className = `flash-message ${type}`;
        notification.style.opacity = '0';
        notification.innerHTML = `
            <i class="fas ${type === 'success' ? 'fa-check' : 'fa-exclamation-triangle'}"></i>
            <span>${message}</span>
        `;
        
        const modalContent = modal.querySelector('.modal-content');
        modalContent.insertBefore(notification, modalContent.firstChild);
        
        notification.offsetHeight;
        notification.style.opacity = '1';
        
        if (type === 'success') {
            setTimeout(() => {
                notification.style.opacity = '0';
                setTimeout(() => notification.remove(), 300);
            }, 5000);
        }
    }

    function showModalNotification(message, type) {
        const modalNotifications = deleteModal.querySelector('.modal-notifications');
        const notification = document.createElement('div');
        notification.className = `modal-notification ${type}`;
        notification.innerHTML = `
            <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i>
            <span>${message}</span>
        `;
        
        modalNotifications.innerHTML = '';
        modalNotifications.appendChild(notification);
        
        if (type === 'success') {
            setTimeout(() => {
                closeDeleteModalFunc();
                // Redirect after modal closes
                setTimeout(() => {
                    window.location.href = '/select_department';
                }, 300);
            }, 1500);
        }
    }

    logsBtn.removeAttribute('disabled');

    logsBtn.addEventListener('click', function() {
        fetch('/department_logs')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const logsList = logsModal.querySelector('.logs-list');
                    logsList.innerHTML = ''; // Clear existing logs
    
                    data.logs.forEach(log => {
                        const logEntry = document.createElement('div');
                        logEntry.className = 'log-entry';
                        logEntry.innerHTML = `
                            <div class="log-info">
                                <div class="log-action">${log.action}</div>
                                <div class="log-details">${log.details}</div>
                                <div class="log-timestamp">
                                    <i class="fas fa-user"></i> ${log.user} | 
                                    <i class="fas fa-clock"></i> ${log.timestamp}
                                </div>
                            </div>
                        `;
                        logsList.appendChild(logEntry);
                    });
    
                    logsModal.style.display = 'block';
                    setTimeout(() => logsModal.classList.add('show'), 50);
                } else {
                    throw new Error(data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('Error', error.message, 'error');
            });
    });

    // Close logs modal
function closeLogsModalFunc() {
    logsModal.classList.remove('show');
    setTimeout(() => logsModal.style.display = 'none', 300);
}

closeLogsModal.onclick = closeLogsModalFunc;
window.onclick = function(event) {
    if (event.target == logsModal) {
        closeLogsModalFunc();
    }
};

}); 