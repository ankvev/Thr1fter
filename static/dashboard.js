let map;
let panorama;

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
 * Exit street view and return to the standard map.
 * Called by the "Exit Street View" button in dashboard.html.
 */
function exitStreetView() {
  if (panorama) panorama.setVisible(false);
  document.getElementById('exit-street-view').classList.add('d-none');
}
