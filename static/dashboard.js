let map;
let panorama;
let markers = [];

/**
 * Entry point called by the Google Maps API once it has loaded.
 * Registered as window.initMap so the Maps script can find it.
 */
window.initMap = function () {
  // Default centre is Sydney CBD – used when geolocation is off or unavailable
  const defaultCenter = { lat: -33.8688, lng: 151.2093 };

  map = new google.maps.Map(document.getElementById('map'), {
    zoom: 13,
    center: defaultCenter,
    mapTypeControl: true,
    streetViewControl: true
  });

  // Only request geolocation if the user has it enabled in settings
  const locationEnabled = localStorage.getItem('thr-location') !== 'false';
  if (navigator.geolocation && locationEnabled) {
    navigator.geolocation.getCurrentPosition(
      pos => map.setCenter({ lat: pos.coords.latitude, lng: pos.coords.longitude }),
      ()  => console.log('Geolocation unavailable – using Sydney default')
    );
  }

  // Load store markers from the JSON embedded by Flask
  const dataEl = document.getElementById('stores-data');
  if (dataEl) {
    const stores = JSON.parse(dataEl.textContent);
    plotStoreMarkers(stores);
  }

  // Clicking anywhere on the map opens a Street View panorama at that point
  map.addListener('click', event => {
    const location = { lat: event.latLng.lat(), lng: event.latLng.lng() };

    panorama = new google.maps.StreetViewPanorama(
      document.getElementById('map'),
      { position: location, pov: { heading: 0, pitch: 0 }, visible: true }
    );

    map.setStreetView(panorama);
    document.getElementById('exit-street-view').classList.remove('d-none');

    // Auto-hide the exit button if the user closes street view via Google's native X
    panorama.addListener('visible_changed', () => {
      if (!panorama.getVisible()) {
        document.getElementById('exit-street-view').classList.add('d-none');
      }
    });
  });
};


/**
 * Plot a marker for every store that has coordinates.
 * Favourited stores get a gold star marker; regular stores get a green pin.
 * Clicking a marker opens an info window with the store name and address.
 *
 * @param {Array} stores - array of store objects from the embedded JSON
 */
function plotStoreMarkers(stores) {

  // Shared info window – reused for each marker so only one is open at a time
  const infoWindow = new google.maps.InfoWindow();

  stores.forEach(store => {
    if (!store.latitude || !store.longitude) return;

    const isFav = store.is_favourite === 1 || store.is_favourite === true;

    const marker = new google.maps.Marker({
      position: { lat: store.latitude, lng: store.longitude },
      map: map,
      title: store.name,
      icon: isFav
        ? {
            // Gold star for favourites
            path: google.maps.SymbolPath.CIRCLE,
            scale: 10,
            fillColor: '#f5c518',
            fillOpacity: 1,
            strokeColor: '#c9a000',
            strokeWeight: 2
          }
        : {
            // Brand green pin for regular stores
            path: google.maps.SymbolPath.CIRCLE,
            scale: 8,
            fillColor: '#3a9e60',
            fillOpacity: 1,
            strokeColor: '#236240',
            strokeWeight: 2
          }
    });

    // Build a compact info window card
    const locationLine = [store.address, store.city, store.state]
      .filter(Boolean).join(', ');

    const content = `
      <div style="max-width:220px; font-family:'Segoe UI',sans-serif; font-size:13px;">
        <strong style="font-size:14px;">${store.name}</strong>
        ${isFav ? ' <span style="color:#c9a000;" title="Favourited">★</span>' : ''}
        <p style="margin:4px 0 0; color:#555;">${locationLine}</p>
        ${store.phone    ? `<p style="margin:4px 0 0;">📞 ${store.phone}</p>` : ''}
        ${store.hours    ? `<p style="margin:4px 0 0;">🕐 ${store.hours}</p>` : ''}
        ${store.website  ? `<p style="margin:4px 0 0;"><a href="${store.website}" target="_blank" rel="noopener">🌐 Website</a></p>` : ''}
      </div>
    `;

    marker.addListener('click', () => {
      infoWindow.setContent(content);
      infoWindow.open(map, marker);
    });

    markers.push(marker);
  });
}


/**
 * Exit street view and return to the standard map.
 * Called by the "Exit Street View" button in dashboard.html.
 */
function exitStreetView() {
  if (panorama) panorama.setVisible(false);
  document.getElementById('exit-street-view').classList.add('d-none');
}