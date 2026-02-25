let map;
    let panorama;

    window.initMap = function () {
        
        const defaultCenter = { lat: -33.8688, lng: 151.2093 };
        
        map = new google.maps.Map(document.getElementById('map'), {
            zoom: 13,
            center: defaultCenter,
            mapTypeControl: true,
            streetViewControl: true
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

        map.addListener("click", (event) => {

        const clickedLocation = {
            lat: event.latLng.lat(),
            lng: event.latLng.lng()
        };

        panorama = new google.maps.StreetViewPanorama(
            document.getElementById("map"),
            {
                position: clickedLocation,
                pov: {
                    heading: 0,
                    pitch: 0
                },
                visible: true
                }
            );

            map.setStreetView(panorama);
        });
    };