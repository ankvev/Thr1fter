/**
 * Run all validation checks before the form submits.
 * Called by the form's onsubmit attribute.
 * @returns {boolean} false to block submission if any check fails
 */
function validateForm() {
  clearErrors();
  let isValid = true;

  const username        = document.getElementById('username').value.trim();
  const password        = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirm_password').value;

  // These regex patterns mirror the server-side checks in app.py
  const hasSymbol      = /[!@#$%^&*(),.?":{}|<>\-_+=\[\]\\;'~`]/.test(password);
  const hasNumber      = /[0-9]/.test(password);
  const userHasSymbol  = /[!@#$%^&*(),.?":{}|<>]/.test(username);

  if (username.length < 3) {
    showError('username', 'Username must be at least 3 characters long.');
    isValid = false;
  } else if (userHasSymbol) {
    showError('username', 'Username can only contain letters, numbers and underscores.');
    isValid = false;
  }

  if (password.length < 12) {
    showError('password', 'Password must be at least 12 characters long.');
    isValid = false;
  } else if (!hasNumber) {
    showError('password', 'Password must contain at least one number.');
    isValid = false;
  } else if (!hasSymbol) {
    showError('password', 'Password must contain at least one special character.');
    isValid = false;
  }

  if (password !== confirmPassword) {
    showError('confirmPassword', 'Passwords do not match.');
    isValid = false;
  }

  return isValid;
}

/**
 * Display an error message below a field and mark it invalid.
 * @param {string} fieldName - logical field name ('username', 'password', 'confirmPassword')
 * @param {string} message   - error text to show
 */
function showError(fieldName, message) {
  const errorDiv  = document.getElementById(fieldName + 'Error');
  // confirm_password input ID differs from the logical fieldName
  const inputId   = fieldName === 'confirmPassword' ? 'confirm_password' : fieldName;
  const inputField = document.getElementById(inputId);

  if (errorDiv) {
    errorDiv.textContent = message;
    errorDiv.classList.add('show');
  }
  if (inputField) inputField.classList.add('is-invalid');
}

/** Clear all error messages and invalid styling. */
function clearErrors() {
  document.querySelectorAll('.error-message').forEach(el => {
    el.classList.remove('show');
    el.textContent = '';
  });
  document.querySelectorAll('input').forEach(el => el.classList.remove('is-invalid'));
}

/**
 * Toggle a password input between visible and hidden.
 * @param {string} fieldId - input element ID
 * @param {string} iconId  - Bootstrap icon element ID
 */
function togglePassword(fieldId, iconId) {
  const field = document.getElementById(fieldId);
  const icon  = document.getElementById(iconId);
  if (!field || !icon) return;

  if (field.type === 'password') {
    field.type = 'text';
    icon.classList.replace('bi-eye', 'bi-eye-slash');
  } else {
    field.type = 'password';
    icon.classList.replace('bi-eye-slash', 'bi-eye');
  }
}
