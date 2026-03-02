let sortOrder = 'asc';

function toggleSection(header) {
    const body = header.nextElementSibling;
    const icon = header.querySelector('.toggle-icon');
    
    body.classList.toggle('collapsed');
    icon.textContent = body.classList.contains('collapsed') ? '+' : '−';
}

function toggleOrder() {
    sortOrder = sortOrder === 'asc' ? 'desc' : 'asc';
    document.getElementById('order-toggle').textContent = 
        sortOrder === 'asc' ? 'Ascending ↑' : 'Descending ↓';
    applyFilters();
}

function applyFilters() {
    const sortEl = document.querySelector('input[name="sort"]:checked');
    const sort = sortEl ? sortEl.value : 'name';
    const cats = [...document.querySelectorAll('input[name="category"]:checked')]
                   .map(i => i.value);

    let results = allStores.filter(store => {
        if (cats.length && !cats.some(c => store.categories.includes(c))) return false;
        return true;
    });

    results.sort((a, b) => {
        const dir = sortOrder === 'asc' ? 1 : -1;
        if (sort === 'name')       return dir * a.name.localeCompare(b.name);
        if (sort === 'date')       return dir * (new Date(a.created_at) - new Date(b.created_at));
        if (sort === 'rating')     return dir * (a.rating - b.rating);
        return 0;
    });

    renderStores(results);
}

function renderStores(stores) {
    const grid = document.getElementById('store-grid');
    if (!stores.length) {
        grid.innerHTML = '<p>No stores match your filters.</p>';
        return;
    }
    grid.innerHTML = stores.map(store => `
        <div class="store-card">
            <h3>${store.name}</h3>
            <p>${store.city}</p>
            <p>${store.address}</p>
            <p>${store.categories.join(', ')}</p>
        </div>
    `).join('');
}