# 02 · Especificación de requerimientos

Formato inspirado en IEEE 830 / ISO/IEC/IEEE 29148. Prioridad según **MoSCoW**
(*Must, Should, Could, Won't*). La columna **Estado** refleja la versión 4.1.

Leyenda de estado: ✅ implementado · ⚠️ implementado con observaciones (ver
[12-seguridad-riesgos-y-deuda-tecnica.md](12-seguridad-riesgos-y-deuda-tecnica.md)) · ⏳ pendiente.

## 1. Actores

| Actor | Descripción | Hereda de |
|---|---|---|
| Visitante | Persona no autenticada | — |
| Usuario autenticado | Cualquier persona con sesión activa | Visitante |
| Estudiante | Usuario de la tabla `users` con `user_active = 1` | Usuario autenticado |
| Coordinador de oficina | Administrador con `admin_priv = 0` | Usuario autenticado |
| Super administrador | Administrador con `admin_priv = 1` | Coordinador de oficina |
| OpenAI API | Sistema externo que genera embeddings y respuestas | — |

## 2. Requerimientos funcionales

### 2.1 Autenticación y sesión

| ID | Requerimiento | Actor | Prioridad | Estado | Implementación |
|---|---|---|---|---|---|
| RF-01 | El sistema debe permitir iniciar sesión con **código** y **contraseña**. | Visitante | Must | ✅ | `POST /login` |
| RF-02 | El sistema debe distinguir si el código pertenece a un estudiante o a un administrador y redirigir a `/home` o `/admin` respectivamente. | Sistema | Must | ✅ | `src/app.py:222` |
| RF-03 | El sistema debe rechazar el acceso de estudiantes inactivos (`user_active ≠ 1`). | Sistema | Must | ✅ | `src/app.py:232` |
| RF-04 | El sistema debe mostrar un mensaje cuando el usuario no exista o la contraseña sea incorrecta. | Sistema | Must | ✅ | `flash()` |
| RF-05 | El sistema debe permitir cerrar sesión. | Usuario autenticado | Must | ✅ | `GET /logout` |
| RF-06 | Las vistas privadas deben redirigir al login si no hay sesión. | Sistema | Must | ✅ | `@login_required` + manejador 401 |

### 2.2 Mapa del campus

| ID | Requerimiento | Actor | Prioridad | Estado | Implementación |
|---|---|---|---|---|---|
| RF-07 | Mostrar un mapa interactivo centrado en el campus del usuario. | Usuario autenticado | Must | ✅ | `GET /home`, `mapa.js` |
| RF-08 | Dibujar el perímetro del campus a partir de su GeoJSON. | Sistema | Must | ✅ | `L.geoJSON` |
| RF-09 | Mostrar un marcador por oficina con ventana emergente (nombre y descripción). | Sistema | Must | ✅ | `L.marker().bindPopup()` |
| RF-10 | Resaltar, centrar y abrir la oficina indicada por el chatbot. | Sistema | Should | ✅ | `highlightOffice()` |

### 2.3 Chatbot

| ID | Requerimiento | Actor | Prioridad | Estado | Implementación |
|---|---|---|---|---|---|
| RF-11 | Permitir escribir preguntas en lenguaje natural desde una ventana flotante. | Usuario autenticado | Must | ✅ | `chatbot.js` |
| RF-12 | Responder usando únicamente el contenido de los PDF cargados por las oficinas como contexto. | Sistema | Must | ✅ | `POST /chatbot` |
| RF-13 | Indicar al final de la respuesta la oficina correspondiente y cómo contactarla. | Sistema | Should | ⚠️ | Prompt en `get_answer()`; `office_info` no se inyecta en el prompt |
| RF-14 | Devolver el `office_id` asociado para resaltarlo en el mapa. | Sistema | Should | ✅ | JSON `{reply, office_id}` |
| RF-15 | Responder saludos simples sin consultar el modelo. | Sistema | Could | ✅ | `is_greeting()` |
| RF-16 | Informar si el chatbot aún no tiene conocimiento cargado. | Sistema | Should | ✅ | `src/app.py:572` |

### 2.4 Gestión de la oficina (coordinador)

| ID | Requerimiento | Actor | Prioridad | Estado | Implementación |
|---|---|---|---|---|---|
| RF-17 | Mostrar un panel con accesos a: ver mapa, editar oficina y entrenar chatbot. | Coordinador | Must | ✅ | `admin.html` |
| RF-18 | Editar nombre, descripción, teléfono y horario de la propia oficina. | Coordinador | Must | ✅ | `POST /office_Edit` |
| RF-19 | Subir un PDF que alimente la base de conocimiento de la oficina. | Coordinador | Must | ✅ | `POST /upload_pdf` |
| RF-20 | Al subir un nuevo PDF, reemplazar el conocimiento anterior de esa oficina y recargar el índice sin reiniciar el servidor. | Sistema | Must | ✅ | `embeddings_<office_id>.pkl` + recarga |

### 2.5 Administración general (super administrador)

| ID | Requerimiento | Actor | Prioridad | Estado | Implementación |
|---|---|---|---|---|---|
| RF-21 | Listar, crear, editar y eliminar **campus** (nombre, lat, lon, archivo GeoJSON). | Super admin | Must | ✅ | `/campus_view`, `/campus_Add`, `/campus_Edit`, `/campus_Delete` |
| RF-22 | Listar, crear, editar y eliminar **oficinas** (campus, nombre, lat, lon, carrera). | Super admin | Must | ✅ | `/office_View`, `/office_Add`, `/office_Edit_Rec`, `/office_Delete` |
| RF-23 | Listar, crear, editar y eliminar **administradores** (código, contraseña, nombre, correo, campus, oficina, privilegio). | Super admin | Must | ✅ | `/admin_View`, `/admin_Add`, `/admin_Edit`, `/admin_Delete` |
| RF-24 | Mostrar en el listado de oficinas el coordinador asignado. | Super admin | Could | ✅ | `LEFT JOIN admins` |
| RF-25 | Mostrar mensajes de confirmación tras cada operación. | Sistema | Should | ✅ | `flash()` |
| RF-26 | Restringir las operaciones de administración según el rol. | Sistema | Must | ⏳ | Ver SEC-01 |
| RF-27 | Administrar cuentas de estudiantes desde la interfaz. | Super admin | Could | ⏳ | No implementado |

## 3. Requerimientos no funcionales

| ID | Categoría (ISO 25010) | Requerimiento | Métrica / criterio | Estado |
|---|---|---|---|---|
| RNF-01 | Seguridad | Las contraseñas se almacenan con hash (Werkzeug). | Nunca en texto plano | ✅ |
| RNF-02 | Seguridad | Todos los formularios y la llamada al chatbot llevan token CSRF. | Flask-WTF `CSRFProtect` | ✅ (solo al ejecutar con `python src/app.py`) |
| RNF-03 | Seguridad | Las consultas SQL son parametrizadas. | Sin concatenación de entradas | ✅ |
| RNF-04 | Seguridad | Los secretos (API key, credenciales BD) no se versionan. | `.env` y `config.py` en `.gitignore` | ✅ |
| RNF-05 | Seguridad | Control de acceso basado en roles en todas las rutas de administración. | 403 para roles no autorizados | ⏳ |
| RNF-06 | Desempeño | Respuesta del chatbot en tiempo aceptable. | p95 < 8 s (dominado por la API externa) | Por medir |
| RNF-07 | Desempeño | Carga del mapa. | < 3 s en red 4G | Por medir |
| RNF-08 | Usabilidad | Interfaz en español y adaptable a móvil. | Bootstrap responsive, `viewport` | ✅ |
| RNF-09 | Usabilidad | El chatbot no debe tapar el mapa de forma permanente. | Ventana minimizable | ✅ |
| RNF-10 | Mantenibilidad | Separación entidad / acceso a datos. | Paquete `models/` | ⚠️ (la mayoría del SQL está en `app.py`) |
| RNF-11 | Portabilidad | Ejecutable en Windows y Linux con Python 3.12. | `requirements.txt` | ✅ |
| RNF-12 | Escalabilidad | Soportar varios campus sin cambios de código. | Datos en tabla `campus` | ✅ |
| RNF-13 | Disponibilidad | Degradación controlada si OpenAI falla. | Mensaje de error amable | ✅ |
| RNF-14 | Costo | Minimizar llamadas a la API. | 1 embedding + 1 completion por pregunta | ✅ |

## 4. Reglas de negocio

| ID | Regla |
|---|---|
| RN-01 | Un estudiante pertenece a un único campus y solo ve el mapa de ese campus. |
| RN-02 | Un administrador pertenece a un campus y a una oficina. |
| RN-03 | `admin_priv = 1` ⇒ super administrador; `admin_priv = 0` ⇒ coordinador de oficina. |
| RN-04 | Solo pueden iniciar sesión los estudiantes con `user_active = 1`. |
| RN-05 | Cada oficina tiene como máximo un archivo de conocimiento activo (`embeddings_<office_id>.pkl`); subir un PDF nuevo reemplaza al anterior. |
| RN-06 | El campus se identifica por su nombre; el nombre no es editable una vez creado. |
| RN-07 | El polígono del campus debe ser un archivo GeoJSON válido. |
| RN-08 | La respuesta del chatbot se asocia a la oficina del fragmento con mayor similitud. |
| RN-09 | Los códigos de estudiante y de administrador comparten espacio de identificadores; si coinciden, prevalece el estudiante al recargar la sesión (ver SEC-05). |

## 5. Matriz de trazabilidad (resumen)

| Requerimiento | Historia de usuario | Caso de prueba |
|---|---|---|
| RF-01 a RF-06 | HU-01, HU-02, HU-03 | CP-01 a CP-06 |
| RF-07 a RF-10 | HU-04, HU-05 | CP-07 a CP-10 |
| RF-11 a RF-16 | HU-06, HU-07, HU-08 | CP-11 a CP-17 |
| RF-17 a RF-20 | HU-09, HU-10 | CP-18 a CP-22 |
| RF-21 | HU-11 | CP-23 a CP-26 |
| RF-22 | HU-12 | CP-27 a CP-29 |
| RF-23 | HU-13 | CP-30 a CP-32 |
| RF-26 / RNF-05 | HU-14 | CP-33, CP-34 |
