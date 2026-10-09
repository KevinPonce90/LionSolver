# Changelog

Todos los cambios relevantes del proyecto se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el
proyecto usa [versionado semántico](https://semver.org/lang/es/) a partir de la
siguiente versión. Las entradas hasta 4.1 se reconstruyeron del historial de Git.

## [Sin publicar]

### Añadido
- Documentación completa en `docs/`: visión, requerimientos, Scrum, arquitectura (C4),
  diagramas UML, base de datos, rutas HTTP, chatbot RAG, instalación, manual de usuario,
  plan de pruebas, y seguridad/riesgos/deuda técnica.
- Script de base de datos reconstruido `docs/database/schema.sql`.
- Plantillas de configuración `.env.example` y `src/config.example.py`.
- `CONTRIBUTING.md` y este `CHANGELOG.md`.

## [4.1] - 2024-12-12

### Cambiado
- Limpieza de `chatbot.js` (se eliminan dos líneas de depuración).

## [4.0] - 2024-11-21

### Añadido
- `office_id` incluido en la información de oficina devuelta por `get_office_info()`.
- Registro en consola de la similitud de cada fragmento recuperado.

### Cambiado
- La oficina asociada a la respuesta pasa a ser la del fragmento **más similar**
  (top‑1) en lugar de la más frecuente entre los 5 recuperados.

## [3.0] - 2024-11-21

### Añadido
- Mapa en el cliente con **Leaflet** (`mapa.js`) y nuevos iconos de marcador normal y
  resaltado.
- Función `highlightOffice()`: el chatbot centra y resalta en el mapa la oficina de la
  respuesta.
- Estilos `mapa.css`.

### Cambiado
- Se sustituye el mapa generado en servidor con **Folium** (iframe) por datos JSON
  renderizados en el navegador.
- La consulta del mapa ya no exige que cada oficina tenga un administrador asignado.

## [2.0] - 2024-10-07

### Añadido
- Carga de PDFs a la carpeta `uploads/` y primer documento de la Unidad de Servicio Social.
- Mensajes de progreso durante la generación de embeddings.

### Cambiado
- `split_text()` divide por palabras las oraciones que exceden el límite de tokens.
- Mejoras de estilo en la ventana del chatbot.

## [1.2] - 2024-10-07

### Añadido
- CRUD de oficinas (`office_view.html`, `/office_View`, `/office_Add`,
  `/office_Edit_Rec`, `/office_Delete`).
- Tarjeta "Ver Oficinas" en el panel de super administrador.

## [1.1] - 2024-10-06

### Añadido
- Aplicación Flask con autenticación de estudiantes y administradores (Flask-Login).
- Mapa del campus con Folium y GeoJSON (`cucei.json`).
- CRUD de campus y administradores.
- Panel de coordinador: edición de oficina y entrenamiento del chatbot.
- Chatbot RAG con OpenAI (embeddings `text-embedding-ada-002`, respuestas `gpt-3.5-turbo`).
- Protección CSRF con Flask-WTF.

## [1.0] - 2024-10-06

### Añadido
- Repositorio inicial y README.

[Sin publicar]: https://github.com/KevinPonce90/LionSolver/compare/c23db33...HEAD
[4.1]: https://github.com/KevinPonce90/LionSolver/commit/c23db33
[4.0]: https://github.com/KevinPonce90/LionSolver/commit/8b764d4
[3.0]: https://github.com/KevinPonce90/LionSolver/commit/470fcbf
[2.0]: https://github.com/KevinPonce90/LionSolver/commit/1b9d7ea
[1.2]: https://github.com/KevinPonce90/LionSolver/commit/2a214f3
[1.1]: https://github.com/KevinPonce90/LionSolver/commit/ca38acc
[1.0]: https://github.com/KevinPonce90/LionSolver/commit/9e1f6d2
