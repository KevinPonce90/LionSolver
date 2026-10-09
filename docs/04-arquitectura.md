# 04 · Arquitectura del sistema

## 1. Estilo arquitectónico

Lion Solver es un **monolito web de renderizado en servidor** (Flask + Jinja2) con un
patrón **MVC simplificado**:

| Capa MVC | Implementación |
|---|---|
| **Modelo** | `src/models/entities/` (entidades `User`, `Admin`) y `src/models/` (`ModelUser`, `ModelAdmin` — acceso a datos). El resto del SQL vive en las funciones de vista. |
| **Vista** | Plantillas Jinja2 en `src/template/` + JavaScript del cliente (`mapa.js`, `chatbot.js`). |
| **Controlador** | Funciones de ruta en `src/app.py`. |

Sobre ese núcleo se añade un **subsistema RAG** (Retrieval-Augmented Generation) en el
mismo proceso, con un índice vectorial en memoria persistido en archivos `.pkl`.

## 2. Modelo C4

### 2.1 Nivel 1 — Contexto del sistema

```mermaid
flowchart TB
    EST([Estudiante<br/><i>Persona</i>])
    COO([Coordinador de oficina<br/><i>Persona</i>])
    SUP([Super administrador<br/><i>Persona</i>])

    LS[["<b>Lion Solver</b><br/>Orienta a los estudiantes hacia la oficina<br/>correcta y la ubica en el mapa del campus"]]

    OAI[["<b>OpenAI API</b><br/><i>Sistema externo</i><br/>Embeddings y generación de texto"]]
    OSM[["<b>OpenStreetMap</b><br/><i>Sistema externo</i><br/>Teselas del mapa base"]]
    CDN[["<b>CDN públicos</b><br/><i>jsDelivr / unpkg</i><br/>Bootstrap y Leaflet"]]

    EST -->|Consulta el mapa y pregunta al chatbot| LS
    COO -->|Actualiza su oficina y sube PDFs| LS
    SUP -->|Administra campus, oficinas y cuentas| LS
    LS -->|Embeddings y respuestas<br/>HTTPS/JSON| OAI
    EST -.->|Descarga teselas| OSM
    EST -.->|Descarga librerías| CDN

    classDef sistema fill:#1168bd,stroke:#0b4884,color:#fff
    classDef externo fill:#999,stroke:#6b6b6b,color:#fff
    classDef persona fill:#08427b,stroke:#052e56,color:#fff
    class LS sistema
    class OAI,OSM,CDN externo
    class EST,COO,SUP persona
```

### 2.2 Nivel 2 — Contenedores

```mermaid
flowchart TB
    U([Usuarios])

    subgraph LS[Lion Solver]
        direction TB
        SPA["<b>Aplicación de navegador</b><br/>HTML/Jinja2, Bootstrap, Leaflet, JS<br/><i>mapa.js · chatbot.js</i>"]
        WEB["<b>Aplicación web</b><br/>Python 3.12 · Flask 3<br/><i>src/app.py</i>"]
        DB[("<b>Base de datos</b><br/>MySQL<br/>campus · offices · admins · users")]
        VEC[("<b>Índice vectorial</b><br/>Pickle en disco<br/>embeddings/embeddings_&lt;id&gt;.pkl<br/>+ copia en memoria")]
        FS[("<b>Almacén de documentos</b><br/>uploads/*.pdf")]
    end

    OAI[[OpenAI API]]
    OSM[[OpenStreetMap]]

    U -->|HTTPS| SPA
    SPA -->|Formularios POST / fetch JSON<br/>+ token CSRF| WEB
    WEB -->|HTML renderizado| SPA
    WEB -->|SQL parametrizado<br/>Flask-MySQLdb| DB
    WEB -->|lee/escribe| VEC
    WEB -->|guarda| FS
    WEB -->|HTTPS| OAI
    SPA -->|HTTPS| OSM
```

### 2.3 Nivel 3 — Componentes de la aplicación web

```mermaid
flowchart LR
    subgraph WEB["Aplicación web Flask (src/app.py)"]
        direction TB
        AUTH["<b>Autenticación</b><br/>/login · /logout<br/>load_user()"]
        MAP["<b>Mapa</b><br/>/home"]
        CAM["<b>CRUD Campus</b><br/>/campus_*"]
        OFF["<b>CRUD Oficinas</b><br/>/office_*"]
        ADM["<b>CRUD Admins</b><br/>/admin_*"]
        CHAT["<b>Chatbot</b><br/>/chatbot"]
        ING["<b>Ingesta</b><br/>/upload_pdf"]
        subgraph RAG[Motor RAG]
            EXT[extract_text_from_pdf]
            SPL[split_text]
            GEN[generate_embeddings]
            STO[save/load_embeddings]
            RET[get_relevant_chunks]
            ANS[get_answer]
        end
        subgraph MOD[models]
            MU[ModelUser]
            MA[ModelAdmin]
            EU[User]
            EA[Admin]
        end
        SEC["Flask-Login<br/>CSRFProtect"]
    end

    AUTH --> MU & MA
    MU --> EU
    MA --> EA
    ING --> EXT --> SPL --> GEN --> STO
    CHAT --> RET --> ANS
    CHAT --> STO
    SEC -.protege.-> MAP & CAM & OFF & ADM & CHAT & ING
```

## 3. Vista de despliegue

```mermaid
flowchart TB
    subgraph Cliente["Dispositivo del usuario"]
        BR[Navegador web]
    end
    subgraph Servidor["Servidor de aplicación (Linux/Windows)"]
        direction TB
        subgraph PY["Proceso Python 3.12"]
            FL[Flask app<br/>src/app.py]
            MEM[(all_embeddings<br/>en memoria)]
        end
        DISK[(Disco<br/>embeddings/ · uploads/)]
        ENV[/.env · src/config.py/]
    end
    subgraph BD["Servidor de base de datos"]
        MY[(MySQL 8 / MariaDB)]
    end
    OAI[[api.openai.com]]
    OSM[[tile.openstreetmap.org]]

    BR -- HTTPS :443 --> FL
    FL -- TCP :3306 --> MY
    FL -- HTTPS --> OAI
    FL --- DISK
    FL --- ENV
    FL --- MEM
    BR -- HTTPS --> OSM
```

En desarrollo todo corre en una sola máquina con el servidor integrado de Werkzeug. Para
producción ver [09-instalacion-y-despliegue.md](09-instalacion-y-despliegue.md).

> **Restricción importante:** el índice vectorial `all_embeddings` es una lista global
> del proceso. Con varios *workers* (p. ej. Gunicorn `-w 4`), un PDF subido en un worker
> no se refleja en los demás hasta reiniciarlos. Mientras no se migre a un almacén
> vectorial compartido, desplegar con **un solo worker** (puede usar varios *threads*).

## 4. Flujos principales

| Flujo | Descripción breve | Diagrama |
|---|---|---|
| Inicio de sesión | Se busca el código en `users` y en `admins`; se valida el hash y se crea la sesión. | [Secuencia 1](05-diagramas-uml.md#41-inicio-de-sesión) |
| Consulta al chatbot | Embedding de la pregunta → top‑5 por similitud coseno → prompt con contexto → respuesta + `office_id`. | [Secuencia 2](05-diagramas-uml.md#42-consulta-al-chatbot-y-resaltado-en-el-mapa) |
| Entrenamiento | PDF → texto → fragmentos ≤ 500 tokens → embeddings → `.pkl` → recarga del índice. | [Secuencia 3](05-diagramas-uml.md#43-entrenamiento-del-chatbot-carga-de-pdf) |
| Visualización del mapa | Consulta campus + oficinas → JSON embebido en la plantilla → Leaflet. | [Secuencia 4](05-diagramas-uml.md#44-carga-del-mapa-del-campus) |

## 5. Decisiones de arquitectura (ADR)

### ADR-001 · Flask como framework web
- **Estado:** aceptada (v1.1).
- **Contexto:** equipo pequeño, necesidad de prototipar rápido con Python (mismo lenguaje que el ecosistema de IA).
- **Decisión:** Flask con extensiones (Flask-Login, Flask-WTF, Flask-MySQLdb).
- **Consecuencias:** curva de aprendizaje baja; la estructura queda a criterio del equipo, lo que derivó en un `app.py` monolítico (ver DT-04).

### ADR-002 · MySQL con SQL directo (sin ORM)
- **Estado:** aceptada (v1.1).
- **Decisión:** `flask_mysqldb` con cursores y consultas parametrizadas.
- **Consecuencias:** control total del SQL; no hay migraciones versionadas ni esquema en el repositorio (se agrega [`docs/database/schema.sql`](database/schema.sql)).

### ADR-003 · RAG con OpenAI en lugar de *fine-tuning*
- **Estado:** aceptada (v1.1, refinada en v2.0 y v4.0).
- **Contexto:** la información cambia por oficina y con frecuencia; el personal no técnico debe poder actualizarla.
- **Decisión:** generar embeddings de fragmentos de PDF y recuperar los más similares para dar contexto a un modelo de chat.
- **Consecuencias:** actualizar conocimiento = subir un PDF; costo por consulta bajo; dependencia de un proveedor externo.

### ADR-004 · Índice vectorial en archivos Pickle + memoria
- **Estado:** aceptada (v1.1), **revisar**.
- **Decisión:** un archivo `.pkl` por oficina, cargados a una lista en memoria al iniciar.
- **Consecuencias:** cero infraestructura adicional; búsqueda lineal O(n) suficiente para decenas de oficinas; no apto para múltiples procesos; `pickle` no debe cargar archivos de origen no confiable.
- **Alternativas para el futuro:** pgvector, Chroma, FAISS, SQLite‑vss.

### ADR-005 · Migración de Folium a Leaflet en el cliente
- **Estado:** aceptada (v3.0), sustituye la generación del mapa en servidor con Folium.
- **Contexto:** el mapa generado por Folium se insertaba como `iframe`, lo que impedía que el chatbot interactuara con él.
- **Decisión:** el servidor entrega JSON (oficinas + GeoJSON) y el cliente dibuja con Leaflet.
- **Consecuencias:** se habilita `highlightOffice()`; menor carga en servidor. `folium` sigue en `requirements.txt` sin uso (DT-03).

### ADR-006 · Oficina de la respuesta = fragmento más similar (top‑1)
- **Estado:** aceptada (v4.0), sustituye a "oficina más frecuente en el top‑5".
- **Consecuencias:** respuesta más predecible cuando una oficina domina la pregunta; puede fallar si el mejor fragmento es genérico. Se recomienda medir con un set de evaluación (ver [08-chatbot-rag.md](08-chatbot-rag.md#6-evaluación-recomendada)).

## 6. Atributos de calidad y tácticas

| Atributo | Táctica aplicada | Mejora propuesta |
|---|---|---|
| Seguridad | Hash de contraseñas, CSRF, SQL parametrizado, `@login_required` | Autorización por rol, límites de tamaño/tipo de archivo, `secure_filename` |
| Disponibilidad | Captura de excepciones en llamadas a OpenAI | Reintentos con *backoff*, *timeouts* |
| Desempeño | Índice en memoria; solo 2 llamadas a la API por pregunta | Vectorizar la similitud con NumPy; caché de embeddings de preguntas frecuentes |
| Mantenibilidad | Paquete `models/` | Blueprints por módulo, capa de servicios, pruebas |
| Portabilidad | Configuración por `.env` | Contenedor Docker |
