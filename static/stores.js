let sortOrder = 'desc';

function toggleSection(header) {
    const body = header.nextElementSibling;
    const icon = header.querySelector('.toggle-icon');

    if (body.classList.contains('collapsed')) {
        body.classList.remove('collapsed');
        body.style.overflow = 'hidden';
        setTimeout(() => body.style.overflow = '', 300);
    } else {
        body.style.overflow = 'hidden';
        body.classList.add('collapsed');
    }

    icon.textContent = body.classList.contains('collapsed') ? '+' : '-';
}

function toggleOrder() {
    sortOrder = sortOrder === 'asc' ? 'desc' : 'asc';
    document.getElementById('order-toggle').textContent = 
        sortOrder === 'asc' ? 'Ascending ↑' : 'Descending ↓';
    applyFilters();
}

function applyFilters() {

}

function renderStores(stores) {

} 