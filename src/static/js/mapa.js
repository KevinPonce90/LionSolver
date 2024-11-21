// Inicializar el mapa
var map = L.map("map").setView([campusLat, campusLon], 17);

// Añadir la capa base al mapa
L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
  maxZoom: 19,
}).addTo(map);

// Variable para almacenar los marcadores de las oficinas
var officeMarkers = {};

// Definir los iconos
var defaultIcon = L.icon({
  iconUrl: "/static/img/location-dot-solid-normal.svg",
  iconSize: [25, 41],
  iconAnchor: [12, 41],
});

var highlightedIcon = L.icon({
  iconUrl: "/static/img/location-dot-solid-selected.svg",
  iconSize: [30, 50],
  iconAnchor: [15, 50],
});

// Agregar los marcadores de las oficinas
offices.forEach(function (office) {
  var marker = L.marker([office.office_lat, office.office_lon], {
    icon: defaultIcon,
  })
    .addTo(map)
    .bindPopup("<b>" + office.office_name + "</b><br>" + office.office_desc);

  // Almacenar el marcador usando el office_id como clave
  officeMarkers[office.office_id] = marker;
});

// Agregar el GeoJSON del campus
var campusLayer = L.geoJSON(campusGeoJSON, {
  style: function (feature) {
    return {
      color: "black", // Color del borde
      weight: 4, // Grosor del borde
      fillColor: "lightblue", // Color de relleno
      fillOpacity: 0.2, // Opacidad del relleno
    };
  },
}).addTo(map);

// Función para resaltar una oficina en el mapa
window.highlightOffice = function (officeId) {
  // Resetear todos los marcadores al icono por defecto
  for (var id in officeMarkers) {
    officeMarkers[id].setIcon(defaultIcon);
  }

  // Verificar si la oficina existe
  if (officeMarkers.hasOwnProperty(officeId)) {
    var marker = officeMarkers[officeId];
    // Cambiar el icono para resaltar
    marker.setIcon(highlightedIcon);
    // Centrar el mapa en la oficina y ajustar el zoom
    map.setView(marker.getLatLng(), 18);
    // Abrir el popup de la oficina
    marker.openPopup();
  } else {
    console.log("Oficina no encontrada en el mapa.");
  }
};
