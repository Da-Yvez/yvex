document.addEventListener('DOMContentLoaded', function () {
    const departmentForm = document.getElementById('departmentForm');
    const passwordForm = document.getElementById('passwordForm');
    const backButton = document.getElementById('backButton');
    const departmentButtons = document.querySelectorAll('.department-button');

    // Function to clear flash messages
    function clearFlashMessages() {
        const flashMessages = document.querySelectorAll('.flash-message');
        flashMessages.forEach(message => message.remove());
    }

    // Add hover animations to buttons
    departmentButtons.forEach(button => {
        button.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-5px)';
        });

        button.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });

        button.addEventListener('click', function(e) {
            e.preventDefault();
            const deptName = this.value;
            
            // Clear any existing flash messages
            clearFlashMessages();
            
            // Update hidden input and department name display
            document.getElementById('department_name').value = deptName;
            document.getElementById('selectedDeptName').textContent = deptName;
            
            // Show password form
            departmentForm.style.display = 'none';
            passwordForm.style.display = 'block';
            
            // Focus on password input
            document.getElementById('passwordInput').focus();
        });
    });

    // Handle back button click
    backButton.addEventListener('click', function() {
        // Clear any existing flash messages
        clearFlashMessages();
        
        passwordForm.style.display = 'none';
        departmentForm.style.display = 'block';
        // Clear password input
        document.getElementById('passwordInput').value = '';
    });

    // Add transitions for form inputs
    document.querySelectorAll('.form-input').forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.style.transform = 'scale(1.02)';
        });
        
        input.addEventListener('blur', function() {
            this.parentElement.style.transform = 'scale(1)';
        });
    });

    // Animate background lights
    function updateLights() {
        const lights = document.querySelectorAll('.light');
        lights.forEach(light => {
            const x = Math.random() * window.innerWidth;
            const y = Math.random() * window.innerHeight;
            light.style.transform = `translate(${x}px, ${y}px)`;
        });
    }

    // Update lights position periodically
    setInterval(updateLights, 8000);
    updateLights(); // Initial position

    // Add Department Modal Functionality
    const modal = document.getElementById('addDepartmentModal');
    const closeBtn = modal.querySelector('.close');
    const cancelBtn = modal.querySelector('.btn-cancel');
    const form = document.getElementById('addDepartmentForm');

    window.handleAddDepartment = function() {
        // Check if user is admin via fetch request
        fetch('/check_admin')
            .then(response => response.json())
            .then(data => {
                if (data.is_admin) {
                    showModal();
                } else {
                    showNotification('Access Denied', 'You must be an admin to add departments', 'error');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('Error', 'Failed to verify admin status', 'error');
            });
    };

    function showModal() {
        modal.style.display = 'block';
        setTimeout(() => modal.classList.add('show'), 50);
    }

    function closeModal() {
        modal.classList.remove('show');
        setTimeout(() => {
            modal.style.display = 'none';
            form.reset();
        }, 300);
    }

    closeBtn.onclick = closeModal;
    cancelBtn.onclick = closeModal;

    window.onclick = function(event) {
        if (event.target == modal) {
            closeModal();
        }
    };

    // Handle form submission
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const formData = new FormData(this);
        const password = formData.get('password');
        const confirmPassword = formData.get('confirm_password');

        if (password !== confirmPassword) {
            showNotification('Error', 'Passwords do not match', 'error');
            return;
        }

        fetch('/add_department', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification('Success', data.message, 'success');
                closeModal();
                // Reload department buttons
                location.reload();
            } else {
                throw new Error(data.message || 'Failed to create department');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Error', error.message, 'error');
        });
    });

    function showNotification(title, message, type) {
        // Remove any existing notifications first
        const existingNotifications = document.querySelectorAll('.flash-message');
        existingNotifications.forEach(notification => notification.remove());
        
        const notification = document.createElement('div');
        notification.className = `flash-message ${type}`;
        notification.innerHTML = `
            <i class="fas ${type === 'success' ? 'fa-check' : 'fa-exclamation-triangle'}"></i>
            <span>${message}</span>
        `;
        
        const flashMessages = document.querySelector('.flash-messages');
        flashMessages.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }
});