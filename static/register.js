function validateForm() {
    clearErrors();
    let isValid = true;

    const username = document.getElementById('username').value;
    const UserHasSymbol = /[!@#$%^&*(),.?":{}|<>]/.test(username);
    const password = document.getElementById('password').value;
    const hasLetter = /[a-zA-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasAlphanumeric = hasLetter && hasNumber;
    const PassHasSymbol = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    const confirmPassword = document.getElementById('confirm_password').value;

    if (username.length < 3) {
        showError('username', 'Username must be at least 3 characters long.');
        isValid = false;
    }

    if (UserHasSymbol) {
        showError('username', 'Username must only contain alphanumeric characters.');
        isValid = false;
    }

    if (password.length < 12) {
        showError('password', 'Password must be at least 12 characters long.');
        isValid = false;
    }

    if (hasAlphanumeric == false) {
        showError('password', 'Password must have at least one number.');
        isValid = false;
    }

    if (PassHasSymbol == false) {
        showError('password', 'Password must have at least one symbol.');
        isValid = false;
    }

    if (password !== confirmPassword) {
        showError('confirmPassword', 'Passwords do not match.');
        isValid = false;
    }

    return isValid;
}

function showError(fieldName, message) {
    const errorDiv = document.getElementById(fieldName + 'Error');
    const inputField = document.getElementById(fieldName === 'confirmPassword' ? 'confirm_password' : fieldName);

    errorDiv.textContent = message;
    errorDiv.classList.add('show');
    inputField.classList.add('error');
}

function clearErrors() {
    const errorMessages = document.querySelectorAll('.error-message');
    const inputs = document.querySelectorAll('input');

    errorMessages.forEach(error => {
        error.classList.remove('show');
        error.textContent = '';
    });

    inputs.forEach(input => {
        input.classList.remove('error');
    });
}


function togglePassword(fieldId, iconId) {
    const field = document.getElementById(fieldId);
    const icon = document.getElementById(iconId);
    
    if (field.type === 'password') {
        // Hidden so show
        field.type = 'text';
        icon.classList.remove('bi-eye');
        icon.classList.add('bi-eye-slash');
    } else {
        // Visible so hide
        field.type = 'password';
        icon.classList.remove('bi-eye-slash');
        icon.classList.add('bi-eye');
    }
}