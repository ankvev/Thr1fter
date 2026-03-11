let map;
let marker;
let autocomplete;
let geocoder;

/**
 * Check whether a lat/lng pair falls within Australia's bounding box.
 * Used to prevent stores from being placed outside Australia.
 */
function isInAustralia(lat, lng) {
  return lat >= -44.0 && lat <= -9.0 && lng >= 113.0 && lng <= 154.0;
}

/**
 * Place (or move) the draggable marker on the map and update the hidden
 * latitude/longitude form fields.
 * @param {google.maps.LatLng} location
 */
function placeMarker(location) {
  const lat = location.lat();
  const lng = location.lng();

  if (!isInAustralia(lat, lng)) {
    alert('Location must be inside Australia.');
    return;
  }

  // Remove any existing marker before placing a new one
  if (marker) marker.setMap(null);

  marker = new google.maps.Marker({
    position:  location,
    map:       map,
    draggable: true,
    animation: google.maps.Animation.DROP
  });

  document.getElementById('latitude').value  = lat;
  document.getElementById('longitude').value = lng;
  updateLocationStatus(lat, lng);

  // Allow the user to fine-tune position by dragging the marker
  marker.addListener('dragend', event => {
    const newLat = event.latLng.lat();
    const newLng = event.latLng.lng();
    document.getElementById('latitude').value  = newLat;
    document.getElementById('longitude').value = newLng;
    updateLocationStatus(newLat, newLng);
    reverseGeocode(event.latLng);
  });
}

/**
 * Geocode a text address to coordinates and centre the map on the result.
 * @param {string} address - full address string
 */
function geocodeAddress(address) {
  geocoder.geocode(
    { address, componentRestrictions: { country: 'AU' } },
    (results, status) => {
      if (status === 'OK') {
        map.setCenter(results[0].geometry.location);
        map.setZoom(15);
        placeMarker(results[0].geometry.location);
      } else {
        console.log('Geocode failed:', status);
      }
    }
  );
}

/**
 * Reverse geocode a LatLng to fill in the address fields.
 * Called after the user drags the marker or clicks the map.
 * @param {google.maps.LatLng} location
 */
function reverseGeocode(location) {
  geocoder.geocode({ location, region: 'AU' }, (results, status) => {
    if (status === 'OK' && results[0]) {
      fillInAddress(results[0].address_components);
      document.getElementById('address').value = results[0].formatted_address;
    }
  });
}

/**
 * Parse a Google address_components array and populate the form fields.
 * @param {Array} components - address_components from a Places/Geocoder result
 */
function fillInAddress(components) {
  let streetNumber = '';
  let route        = '';

  for (const component of components) {
    const type = component.types[0];
    if      (type === 'street_number')              streetNumber = component.short_name;
    else if (type === 'route')                      route        = component.long_name;
    else if (type === 'locality')                   document.getElementById('city').value      = component.long_name;
    else if (type === 'administrative_area_level_1')document.getElementById('state').value     = component.short_name;
    else if (type === 'postal_code')                document.getElementById('post_code').value = component.short_name;
  }

  if (streetNumber && route) {
    document.getElementById('address').value = `${streetNumber} ${route}`;
  }
}

/** Build a full address string from the current form values for geocoding. */
function getFullAddress() {
  const address  = document.getElementById('address').value.trim();
  const city     = document.getElementById('city').value.trim();
  const state    = document.getElementById('state').value.trim();
  const postCode = document.getElementById('post_code').value.trim();
  if (!address || !city) return null;
  return `${address}, ${city}${state ? ', ' + state : ''}${postCode ? ' ' + postCode : ''}`;
}

/** Update the on-screen location status text once coordinates are set. */
function updateLocationStatus(lat, lng) {
  const el = document.getElementById('locationStatus');
  el.innerHTML = `<i class="bi bi-check-circle-fill text-success me-1"></i>Location set: ${lat.toFixed(6)}, ${lng.toFixed(6)}`;
}

/**
 * Google Maps callback – called once the API script has loaded.
 * Sets up the map, geocoder, click listener and Places Autocomplete.
 */
window.initMap = function () {
  const defaultCenter = { lat: -33.8688, lng: 151.2093 }; // Sydney CBD fallback

  map = new google.maps.Map(document.getElementById('map'), {
    zoom: 13,
    center: defaultCenter,
    mapTypeControl: true,
    streetViewControl: false
  });

  geocoder = new google.maps.Geocoder();

  // Centre on user's location if available
  if (navigator.geolocation) {
    navigator.geolocation.getCurrentPosition(
      pos => map.setCenter({ lat: pos.coords.latitude, lng: pos.coords.longitude }),
      ()  => console.log('Geolocation unavailable – using Sydney default')
    );
  }

  // Click on the map to drop a pin
  map.addListener('click', event => {
    const lat = event.latLng.lat();
    const lng = event.latLng.lng();
    if (!isInAustralia(lat, lng)) {
      alert('Please select a location within Australia (mainland or Tasmania).');
      return;
    }
    placeMarker(event.latLng);
    reverseGeocode(event.latLng);
  });

  // Set up Places Autocomplete restricted to Australia
  const addressInput = document.getElementById('address');
  autocomplete = new google.maps.places.Autocomplete(addressInput, {
    componentRestrictions: { country: 'au' },
    fields: ['address_components', 'geometry', 'name']
  });

  let placeSelected = false;

  autocomplete.addListener('place_changed', () => {
    const place = autocomplete.getPlace();
    if (!place.geometry) return;
    placeSelected = true;
    map.setCenter(place.geometry.location);
    map.setZoom(15);
    placeMarker(place.geometry.location);
    fillInAddress(place.address_components);
  });

  // Geocode when the user manually types and blurs the address field
  addressInput.addEventListener('blur', () => {
    if (placeSelected) { placeSelected = false; return; }
    const full = getFullAddress();
    if (full) geocodeAddress(full);
  });

  // Also geocode when city/state/post_code are blurred
  ['city', 'state', 'post_code'].forEach(id => {
    document.getElementById(id)?.addEventListener('blur', () => {
      const full = getFullAddress();
      if (full) geocodeAddress(full);
    });
  });
};

// ── Form submit validation ────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('addStoreForm');

  // Prevent the Enter key from submitting the form mid-autocomplete
  form.addEventListener('keydown', e => {
    if (e.key === 'Enter') e.preventDefault();
  });

  // Require a map pin before allowing submission
  form.addEventListener('submit', e => {
    const lat = document.getElementById('latitude').value;
    const lng = document.getElementById('longitude').value;
    if (!lat || !lng) {
      e.preventDefault();
      alert('Please set a location on the map before submitting.');
    }
  });
});


