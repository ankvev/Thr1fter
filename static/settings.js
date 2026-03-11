// ─── Dark mode ────────────────────────────────────────────────────────────────

const darkToggle = document.getElementById('darkModeToggle');

/**
 * Apply a theme to the document and persist it in localStorage.
 * @param {'light'|'dark'} theme
 */
function applyTheme(theme) {
  document.documentElement.setAttribute('data-bs-theme', theme);
  localStorage.setItem('thr-theme', theme);
}

// Initialise the toggle to match the currently active theme
darkToggle.checked = (localStorage.getItem('thr-theme') || 'light') === 'dark';

darkToggle.addEventListener('change', () => {
  applyTheme(darkToggle.checked ? 'dark' : 'light');
});


// ─── Colourblind mode ─────────────────────────────────────────────────────────

const cbToggle = document.getElementById('colourblindToggle');

/**
 * Enable or disable the colourblind CSS class and persist the choice.
 * @param {boolean} enabled
 */
function applyColourblind(enabled) {
  document.documentElement.classList.toggle('thr-colourblind', enabled);
  localStorage.setItem('thr-colourblind', enabled ? 'true' : 'false');
}

// Restore saved state on page load
cbToggle.checked = localStorage.getItem('thr-colourblind') === 'true';
applyColourblind(cbToggle.checked);

cbToggle.addEventListener('change', () => applyColourblind(cbToggle.checked));


// ─── Text size ────────────────────────────────────────────────────────────────

const sizeMap = { small: '14px', normal: '16px', large: '19px' };

/**
 * Apply a font size to the root element and highlight the active button.
 * @param {'small'|'normal'|'large'} size
 */
function applyTextSize(size) {
  document.documentElement.style.fontSize = sizeMap[size] || '16px';
  localStorage.setItem('thr-text-size', size);

  // Update button active states
  document.querySelectorAll('.text-size-btn').forEach(btn => {
    const isActive = btn.dataset.size === size;
    btn.classList.toggle('thr-btn-primary', isActive);
    btn.classList.toggle('thr-btn-outline', !isActive);
  });
}

// Restore saved size
applyTextSize(localStorage.getItem('thr-text-size') || 'normal');

document.querySelectorAll('.text-size-btn').forEach(btn => {
  btn.addEventListener('click', () => applyTextSize(btn.dataset.size));
});


// ─── Location preference ──────────────────────────────────────────────────────

const locationToggle = document.getElementById('locationToggle');

// Default to enabled if no preference has been saved yet
locationToggle.checked = localStorage.getItem('thr-location') !== 'false';

locationToggle.addEventListener('change', () => {
  localStorage.setItem('thr-location', locationToggle.checked ? 'true' : 'false');
});


// ─── Password show/hide ───────────────────────────────────────────────────────

/**
 * Toggle a password input between visible and hidden text.
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


// ─── Change password – client-side match validation ──────────────────────────

document.getElementById('changePasswordForm')?.addEventListener('submit', e => {
  const newPw     = document.getElementById('new_pw').value;
  const confirmPw = document.getElementById('conf_pw').value;
  const errEl     = document.getElementById('pwMatchError');

  if (newPw !== confirmPw) {
    e.preventDefault();
    errEl.textContent = 'Passwords do not match.';
  } else {
    errEl.textContent = '';
  }
});
