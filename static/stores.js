let sortOrder = 'desc';
let allStores = [];

document.addEventListener("DOMContentLoaded", () => {

    const dataElement = document.getElementById("stores-data");

    if (dataElement) {
        allStores = JSON.parse(dataElement.textContent);
    }

    applyFilters();
});

function toggleOrder() {
    sortOrder = sortOrder === 'asc' ? 'desc' : 'asc';

    document.getElementById('order-toggle').innerHTML =
        sortOrder === 'asc'
        ? 'Ascending <i class="bi bi-arrow-up"></i>'
        : 'Descending <i class="bi bi-arrow-down"></i>';

    applyFilters();
}


function applyFilters() {

    let filtered = [...allStores];

    const checkedCategories = [...document.querySelectorAll('input[name="category"]:checked')]
        .map(cb => cb.value);

    if (checkedCategories.length > 0) {
        filtered = filtered.filter(store =>
            checkedCategories.some(cat => store[cat] === 1 || store[cat] === true)
        );
    }

    const sortType = document.querySelector('input[name="sort"]:checked').value;

    filtered.sort((a, b) => {

        let valA = a[sortType];
        let valB = b[sortType];

        if (sortType === "date") {
            valA = new Date(valA);
            valB = new Date(valB);
        }

        if (valA == null) return 1;
        if (valB == null) return -1;

        if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
        if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
        return 0;

    });

    renderStores(filtered);
}


function renderStores(stores) {

    const grid = document.getElementById("store-grid");
    const count = document.getElementById("store-count");
    const noStores = document.getElementById("no-stores");

    grid.innerHTML = "";

    count.textContent = `${stores.length} store${stores.length !== 1 ? 's' : ''}`;

    if (stores.length === 0) {
        noStores.classList.remove("d-none");
        return;
    }

    noStores.classList.add("d-none");

    stores.forEach(store => {

        const card = document.createElement("div");
        card.className = "col";

        // Build the location line
        let locationParts = [store.address, store.city];
        if (store.state)     locationParts.push(store.state);
        if (store.post_code) locationParts.push(store.post_code);
        const location = locationParts.join(', ');

        // Build category tags from whichever boolean flags are set
        const categoryLabels = {
            general_clothing: 'General Clothing', vintage_retro: 'Vintage / Retro',
            y2k: 'Y2K', grunge: 'Grunge', streetwear: 'Streetwear',
            designer_luxury_resale: 'Designer / Luxury', formal_evening: 'Formal / Evening',
            workwear: 'Workwear', sportswear_activewear: 'Sportswear',
            childrens_clothing: "Children's", shoes_footwear: 'Shoes',
            bags_purses: 'Bags / Purses', jewellery: 'Jewellery',
            hats_caps: 'Hats', belts_scarves: 'Belts / Scarves',
            furniture: 'Furniture', homewares_kitchenware: 'Homewares',
            antiques: 'Antiques', art_prints: 'Art / Prints',
            linen_textiles: 'Linen', lamps_lighting: 'Lamps',
            books: 'Books', vinyl_music: 'Vinyl',
            dvds_vhs_games: 'DVDs / Games', collectibles_memorabilia: 'Collectibles',
            toys_figurines: 'Toys', op_charity_shop: 'Op / Charity',
            mixed_goods: 'Mixed Goods', electrical_tech: 'Electrical',
            sports_equipment: 'Sports Equip.', craft_fabric_sewing: 'Craft / Sewing',
            instruments: 'Instruments'
        };

        const activeCats = Object.entries(categoryLabels)
            .filter(([key]) => store[key] === 1 || store[key] === true)
            .map(([, label]) => `<span class="thr-cat-tag">${label}</span>`)
            .join('');

        const isFav = store.is_favourite === 1 || store.is_favourite === true;

        card.innerHTML = `
        <div class="card thr-store-card h-100 shadow-sm">
            <div class="card-body d-flex flex-column gap-2">

                <!-- Title row with heart button -->
                <div class="d-flex justify-content-between align-items-start gap-2">
                    <h5 class="card-title fw-bold mb-0">${store.name}</h5>
                    <button
                        class="thr-fav-btn flex-shrink-0"
                        data-store-id="${store.id}"
                        aria-label="${isFav ? 'Remove from favourites' : 'Add to favourites'}"
                        title="${isFav ? 'Remove from favourites' : 'Add to favourites'}"
                        onclick="toggleFavourite(this, ${store.id})"
                    >
                        <i class="bi bi-heart${isFav ? '-fill thr-fav-active' : ''} fs-5"></i>
                    </button>
                </div>

                <!-- Address -->
                <p class="text-muted small mb-0">
                    <i class="bi bi-geo-alt me-1"></i>${location}
                </p>

                <!-- Phone -->
                ${store.phone ? `
                <p class="small mb-0">
                    <i class="bi bi-telephone me-1 text-muted"></i>${store.phone}
                </p>` : ''}

                <!-- Hours -->
                ${store.hours ? `
                <p class="small mb-0">
                    <i class="bi bi-clock me-1 text-muted"></i>${store.hours}
                </p>` : ''}

                <!-- Website -->
                ${store.website ? `
                <p class="small mb-0">
                    <i class="bi bi-globe me-1 text-muted"></i>
                    <a href="${store.website}" target="_blank" rel="noopener" class="thr-link">${store.website}</a>
                </p>` : ''}

                <!-- Description -->
                ${store.description ? `
                <p class="small text-muted mb-0">${store.description.substring(0, 160)}${store.description.length > 160 ? '…' : ''}</p>
                ` : ''}

                <!-- Category tags -->
                ${activeCats ? `
                <div class="thr-cat-tags d-flex flex-wrap gap-1 mt-1">
                    ${activeCats}
                </div>` : ''}

            </div>
        </div>
        `;

        grid.appendChild(card);

    });
}


/**
 * Toggle a store's favourite status via the API endpoint.
 * Updates the heart icon and aria-label immediately on success.
 * @param {HTMLElement} btn   - the button element that was clicked
 * @param {number}      storeId
 */
async function toggleFavourite(btn, storeId) {
    try {
        const res = await fetch(`/api/favourite/${storeId}`, { method: 'POST' });
        if (!res.ok) throw new Error('Request failed');

        const data = await res.json();
        const icon = btn.querySelector('i');
        const isFav = data.is_favourite;

        icon.className = `bi bi-heart${isFav ? '-fill thr-fav-active' : ''} fs-5`;
        btn.setAttribute('aria-label', isFav ? 'Remove from favourites' : 'Add to favourites');
        btn.setAttribute('title',      isFav ? 'Remove from favourites' : 'Add to favourites');

        // Keep allStores in sync so re-renders preserve the new state
        const storeEntry = allStores.find(s => s.id === storeId);
        if (storeEntry) storeEntry.is_favourite = isFav ? 1 : 0;

    } catch (err) {
        console.error('Failed to toggle favourite:', err);
    }
}