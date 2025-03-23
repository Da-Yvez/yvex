// Add smooth transitions for form interactions
document.addEventListener('DOMContentLoaded', function() {
    // Add animation to form inputs on focus
    const inputs = document.querySelectorAll('.form-input');
    inputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.style.transform = 'scale(1.02)';
        });
        
        input.addEventListener('blur', function() {
            this.parentElement.style.transform = 'scale(1)';
        });
    });

    // Animate error messages
    const errorMessages = document.querySelectorAll('.error-message');
    errorMessages.forEach(message => {
        message.style.animation = 'slideIn 0.3s ease-out';
    });

    // Add hover effect to logo
    const logoText = document.querySelector('.logo-text');
    if (logoText) {
        logoText.addEventListener('mouseover', function() {
            this.style.transform = 'scale(1.1)';
            this.style.transition = 'transform 0.3s ease';
        });

        logoText.addEventListener('mouseout', function() {
            this.style.transform = 'scale(1)';
        });
    }

    // Animate background lights
    function updateLights() {
        const lights = document.querySelectorAll('.light');
        lights.forEach(light => {
            const x = Math.random() * window.innerWidth;
            const y = Math.random() * window.innerHeight;
            light.style.transform = `translate(${x}px, ${y}px)`;
        });
    }

    // Initial position update
    updateLights();
});
