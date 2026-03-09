// Global variables
let map;
let marker;
let autocomplete;
let geocoder;

// Australia bounding box check (global so it can be used by placeMarker and click listener)
function isInAustralia(lat, lng) {
    return (
        lat >= -44.0 &&
        lat <= -9.0 &&
        lng >= 113.0 &&
        lng <= 154.0
    );
}

function placeMarker(location) {
    const lat = location.lat();
    const lng = location.lng();

    if (!isInAustralia(lat, lng)) {
        alert("Location must be inside Australia.");
        return;
    }
    
    if (marker) {
        marker.setMap(null);
    }
    
    marker = new google.maps.Marker({
        position: location,
        map: map,
        draggable: true,
        animation: google.maps.Animation.DROP
    });
    
    document.getElementById('latitude').value = lat;
    document.getElementById('longitude').value = lng;
    
    updateLocationStatus(lat, lng);
    
    marker.addListener('dragend', (event) => {
        const newLat = event.latLng.lat();
        const newLng = event.latLng.lng();
        document.getElementById('latitude').value = newLat;
        document.getElementById('longitude').value = newLng;
        updateLocationStatus(newLat, newLng);
        reverseGeocode(event.latLng);
    });
}

function geocodeAddress(address) {
    geocoder.geocode({
        address: address,
        componentRestrictions: { country: "AU" }
    }, (results, status) => {
        if (status === 'OK') {
            map.setCenter(results[0].geometry.location);
            map.setZoom(15);
            placeMarker(results[0].geometry.location);
        } else {
            console.log('Geocode failed: ' + status);
        }
    });
}

function reverseGeocode(location) {
    geocoder.geocode({
        location: location,
        region: "AU"
    }, (results, status) => {
        if (status === 'OK' && results[0]) {
            fillInAddress(results[0].address_components);
            document.getElementById('address').value = results[0].formatted_address;
        }
    });
}

function fillInAddress(components) {
    const componentForm = {
        street_number: 'short_name',
        route: 'long_name',
        locality: 'long_name',
        administrative_area_level_1: 'short_name',
        postal_code: 'short_name'
    };
    
    let streetNumber = '';
    let route = '';
    
    for (const component of components) {
        const addressType = component.types[0];
        if (componentForm[addressType]) {
            const val = component[componentForm[addressType]];
            if (addressType === 'street_number') streetNumber = val;
            else if (addressType === 'route') route = val;
            else if (addressType === 'locality') document.getElementById('city').value = val;
            else if (addressType === 'administrative_area_level_1') document.getElementById('state').value = val;
            else if (addressType === 'postal_code') document.getElementById('post_code').value = val;
        }
    }
    
    if (streetNumber && route) {
        document.getElementById('address').value = streetNumber + ' ' + route;
    }
}

function getFullAddress() {
    const address = document.getElementById('address').value.trim();
    const city = document.getElementById('city').value.trim();
    const state = document.getElementById('state').value.trim();
    const postCode = document.getElementById('post_code').value.trim();
    
    if (!address || !city) return null;
    
    return `${address}, ${city}${state ? ', ' + state : ''}${postCode ? ' ' + postCode : ''}`.trim();
}

function updateLocationStatus(lat, lng) {
    document.getElementById('locationStatus').innerHTML = 
        `✓ Location set: ${lat.toFixed(6)}, ${lng.toFixed(6)}`;
    document.getElementById('locationStatus').style.color = '#27ae60';
}

window.initMap = function () {
    const defaultCenter = { lat: -33.8688, lng: 151.2093 };
    
    map = new google.maps.Map(document.getElementById('map'), {
        zoom: 13,
        center: defaultCenter,
        mapTypeControl: true,
        streetViewControl: false
    });
    
    geocoder = new google.maps.Geocoder();
    
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(
            (position) => {
                map.setCenter({
                    lat: position.coords.latitude,
                    lng: position.coords.longitude
                });
            },
            () => {
                console.log("Geolocation failed, using Sydney default");
            }
        );
    }
    
    map.addListener('click', (event) => {
        const lat = event.latLng.lat();
        const lng = event.latLng.lng();

        if (!isInAustralia(lat, lng)) {
            alert("Please select a location within Australia (mainland or Tasmania).");
            return;
        }

        placeMarker(event.latLng);
        reverseGeocode(event.latLng);
    });
    
    // Autocomplete setup
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

    // Blur events for manual address entry
    addressInput.addEventListener('blur', () => {
        if (placeSelected) {
            placeSelected = false;
            return;
        }
        const fullAddr = getFullAddress();
        if (fullAddr) geocodeAddress(fullAddr);
    });

    ['city', 'state', 'post_code'].forEach(id => {
        document.getElementById(id).addEventListener('blur', () => {
            const fullAddr = getFullAddress();
            if (fullAddr) geocodeAddress(fullAddr);
        });
    });
};

// Form validation – require location
document.addEventListener("DOMContentLoaded", function () {
    // Prevent Enter key from submitting the form
    document.getElementById('addStoreForm').addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
        }
    });

    document.getElementById('addStoreForm').addEventListener('submit', function(e) {
        const lat = document.getElementById('latitude').value;
        const lng = document.getElementById('longitude').value;

        if (!lat || !lng) {
            e.preventDefault();
            alert('Please set a location on the map!');
        }
    });
});