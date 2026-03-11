/**
 * Toggle a password input between 'password' and 'text' type.
 * @param {string} fieldId - ID of the <input> element
 * @param {string} iconId  - ID of the <i> Bootstrap icon element
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

// Apply saved preferences immediately so auth pages also respect user settings
(function () {
  const theme = localStorage.getItem('thr-theme') || 'light';
  document.documentElement.setAttribute('data-bs-theme', theme);

  const sizeMap = { small: '14px', normal: '16px', large: '19px' };
  const size    = localStorage.getItem('thr-text-size') || 'normal';
  document.documentElement.style.fontSize = sizeMap[size] || '16px';

  if (localStorage.getItem('thr-colourblind') === 'true') {
    document.documentElement.classList.add('thr-colourblind');
  }
})();
