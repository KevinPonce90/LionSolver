# 05 · Diagramas UML

Todos los diagramas están en Mermaid y reflejan el código de la versión 4.1.

| # | Diagrama UML | Tipo | Sección |
|---|---|---|---|
| 1 | Casos de uso | Comportamiento | [§1](#1-diagrama-de-casos-de-uso) |
| 2 | Clases | Estructura | [§2](#2-diagrama-de-clases) |
| 3 | Paquetes | Estructura | [§3](#3-diagrama-de-paquetes) |
| 4 | Secuencia (×5) | Interacción | [§4](#4-diagramas-de-secuencia) |
| 5 | Actividad (×3) | Comportamiento | [§5](#5-diagramas-de-actividad) |
| 6 | Máquina de estados (×3) | Comportamiento | [§6](#6-diagramas-de-estados) |
| 7 | Componentes | Estructura | [§7](#7-diagrama-de-componentes) |
| 8 | Despliegue | Estructura | [§8](#8-diagrama-de-despliegue) |

---

## 1. Diagrama de casos de uso

```mermaid
flowchart LR
    EST(("🧑‍🎓<br/>Estudiante"))
    COO(("🧑‍💼<br/>Coordinador<br/>de oficina"))
    SUP(("🛡️<br/>Super<br/>administrador"))
    OAI(("☁️<br/>OpenAI API"))

    subgraph SYS["Sistema Lion Solver"]
        direction TB
        UC01([CU-01 Iniciar sesión])
        UC02([CU-02 Cerrar sesión])
        UC03([CU-03 Ver mapa del campus])
        UC04([CU-04 Consultar al chatbot])
        UC05([CU-05 Resaltar oficina en el mapa])
        UC06([CU-06 Editar datos de su oficina])
        UC07([CU-07 Entrenar chatbot con PDF])
        UC08([CU-08 Gestionar campus])
        UC09([CU-09 Gestionar oficinas])
        UC10([CU-10 Gestionar administradores])
        UC11([CU-11 Validar credenciales])
        UC12([CU-12 Generar embeddings])
    end

    EST --- UC01 & UC02 & UC03 & UC04
    COO --- UC01 & UC02 & UC03 & UC04 & UC06 & UC07
    SUP --- UC08 & UC09 & UC10
    SUP -. "hereda de" .-> COO

    UC01 -. "«include»" .-> UC11
    UC04 -. "«include»" .-> UC12
    UC07 -. "«include»" .-> UC12
    UC05 -. "«extend»" .-> UC04
    UC12 --- OAI
```

> Mermaid no tiene notación nativa de casos de uso; se representa con nodos ovalados
> (casos de uso), círculos (actores) y relaciones `«include»` / `«extend»` punteadas.

### 1.1 Especificación de casos de uso principales

#### CU-01 · Iniciar sesión

| Campo | Detalle |
|---|---|
| Actor principal | Estudiante, Coordinador, Super administrador |
| Precondición | El usuario existe en `users` o `admins`. |
| Disparador | El usuario abre `/login`. |
| Flujo principal | 1. Ingresa código y contraseña. 2. El sistema busca el código en `users` y en `admins`. 3. Valida el hash de contraseña. 4. Si es estudiante activo → `/home`; si es administrador → `/admin`. |
| Flujos alternos | 3a. Contraseña incorrecta o estudiante inactivo → mensaje y permanece en login. 2a. Código inexistente → "Usurario no encontrado". |
| Postcondición | Sesión de Flask-Login creada con el `id` = código. |

#### CU-04 · Consultar al chatbot

| Campo | Detalle |
|---|---|
| Actor principal | Usuario autenticado |
| Actor secundario | OpenAI API |
| Precondición | Sesión activa; vista `/home` cargada. |
| Flujo principal | 1. Abre la ventana del chatbot. 2. Escribe la pregunta y pulsa *Enviar* o *Enter*. 3. El cliente hace `POST /chatbot` con token CSRF. 4. El sistema obtiene el embedding de la pregunta. 5. Selecciona los 5 fragmentos más similares. 6. Envía el contexto y la pregunta al modelo de chat. 7. Devuelve `{reply, office_id}`. 8. El cliente muestra la respuesta y ejecuta CU-05. |
| Flujos alternos | 4a. No hay embeddings cargados → mensaje "El chatbot aún no está listo…". 6a. Error del modelo → "Lo siento, ha ocurrido un error al obtener la respuesta." 3a. Error HTTP → "Lo siento, ha ocurrido un error." Pregunta = saludo exacto → respuesta fija sin llamar al modelo de chat. |
| Postcondición | Respuesta visible; oficina resaltada si existe en el mapa. |

#### CU-07 · Entrenar chatbot con PDF

| Campo | Detalle |
|---|---|
| Actor principal | Coordinador de oficina |
| Precondición | Sesión de administrador; la cuenta tiene oficina asignada. |
| Flujo principal | 1. Abre "Entrenar Chatbot". 2. Selecciona un PDF. 3. El sistema lo guarda en `uploads/`. 4. Extrae el texto. 5. Lo divide en fragmentos ≤ 500 tokens. 6. Genera un embedding por fragmento. 7. Guarda `embeddings/embeddings_<office_id>.pkl`. 8. Recarga el índice global. 9. Muestra confirmación. |
| Flujos alternos | 4a. Texto vacío → mensaje de error. 6a. Falla un fragmento → se omite y continúa. |
| Postcondición | El chatbot responde con la nueva información de la oficina. |

---

## 2. Diagrama de clases

```mermaid
classDiagram
    direction LR

    class UserMixin {
        <<Flask-Login>>
        +is_authenticated bool
        +is_active bool
        +is_anonymous bool
        +get_id() str
    }

    class User {
        <<entity>>
        +id : int  «user_cod»
        +password : str | bool | None
        +campus : str
        +fullname : str
        +email : str
        +career : str
        +active : int
        +User(cod, password, campus, fullname, email, career, active)
        +check_password(hashed_password, password)$ bool
    }

    class Admin {
        <<entity>>
        +id : int  «admin_cod»
        +password : str | bool | None
        +campus : str
        +career : int  «admin_office»
        +fullname : str
        +email : str
        +priv : int  «0 regular / 1 super»
        +Admin(cod, password, campus, office, fullname, email, priv)
        +check_password(hashed_password, password)$ bool
    }

    class ModelUser {
        <<repository>>
        +login(db, user)$ User | None
        +get_by_cod(db, cod)$ User | None
    }

    class ModelAdmin {
        <<repository>>
        +login(db, admin)$ Admin | None
        +get_by_cod(db, cod)$ Admin | None
    }

    class RagEngine {
        <<module functions · app.py>>
        +all_embeddings : list~EmbeddingRecord~
        +extract_text_from_pdf(pdf_file) str
        +split_text(text, max_tokens=500) list~str~
        +generate_embeddings(chunks, office_id) list~EmbeddingRecord~
        +save_embeddings(embeddings, filename) void
        +load_embeddings(filename) list~EmbeddingRecord~
        +get_relevant_chunks(question, embeddings, top_k=5) list
        +get_answer(question, context, office_info) str
        +get_office_info(office_id) dict
    }

    class EmbeddingRecord {
        <<dict>>
        +embedding : float[1536]
        +text : str
        +office_id : str
    }

    class Campus {
        <<tabla>>
        +campus_name : varchar PK
        +campus_coords : JSON
        +campus_lat : decimal
        +campus_lon : decimal
    }

    class Office {
        <<tabla>>
        +office_id : int PK
        +office_campus : varchar FK
        +office_name : varchar
        +office_desc : text
        +office_phone : varchar
        +office_hours : varchar
        +office_lat : decimal
        +office_lon : decimal
        +office_career : varchar
    }

    UserMixin <|-- User
    UserMixin <|-- Admin
    ModelUser ..> User : crea
    ModelAdmin ..> Admin : crea
    RagEngine "1" o-- "*" EmbeddingRecord : all_embeddings
    EmbeddingRecord "*" --> "1" Office : office_id
    Campus "1" *-- "*" Office : contiene
    User "*" --> "1" Campus : campus
    Admin "*" --> "1" Campus : campus
    Admin "0..1" --> "1" Office : career
    RagEngine ..> Office : consulta
```

**Notas de diseño**

- `password` en las entidades reutiliza el mismo atributo para tres significados: la
  contraseña en claro (al construir la credencial), el resultado booleano de
  `check_password` (tras el login) y `None` (al recargar desde sesión). Ver DT-05.
- En `Admin`, la oficina se guarda en el atributo `career` para que `upload_pdf` use
  `current_user.career` como `office_id` de los embeddings.
- `RagEngine` no es una clase real: agrupa las funciones de módulo de `src/app.py`
  relacionadas con el chatbot. Se modela así para mostrar sus responsabilidades.

---

## 3. Diagrama de paquetes

```mermaid
flowchart TB
    subgraph src["📦 src"]
        APP["app.py<br/>«controlador + RAG»"]
        APP2["app2.py<br/>«legado»"]
        CFG["config.py<br/>«no versionado»"]
        subgraph models["📦 models"]
            MU[ModelUser]
            MA[ModelAdmin]
            subgraph entities["📦 entities"]
                EU[User]
                EA[Admin]
            end
        end
        subgraph template["📦 template"]
            LAY[layout.html]
            HOME[home.html]
            ADMH[admin.html / admin_rec.html]
            VIEWS[campus_view / office_view / admin_view]
            subgraph auth["📦 auth"]
                LOG[login.html]
            end
        end
        subgraph static["📦 static"]
            JS[js: mapa.js · chatbot.js]
            CSS[css]
            IMG[img]
            JSON[json: cucei.json]
        end
    end
    EXT["📦 Librerías externas<br/>flask · flask_login · flask_wtf · flask_mysqldb<br/>openai · tiktoken · PyPDF2 · sklearn · numpy"]

    APP --> models
    APP --> CFG
    APP --> template
    APP --> EXT
    MU --> EU
    MA --> EA
    HOME --> JS
    template --> LAY
```

---

## 4. Diagramas de secuencia

### 4.1 Inicio de sesión

```mermaid
sequenceDiagram
    autonumber
    actor U as Usuario
    participant B as Navegador
    participant F as Flask /login
    participant MU as ModelUser
    participant MA as ModelAdmin
    participant DB as MySQL
    participant FL as Flask-Login

    U->>B: Ingresa código y contraseña
    B->>F: POST /login (codigo, password, csrf_token)
    F->>MU: login(db, User(codigo, password))
    MU->>DB: SELECT ... FROM users WHERE user_cod = %s
    DB-->>MU: fila | None
    MU-->>F: User(password = check_password_hash(...)) | None
    F->>MA: login(db, Admin(codigo, password))
    MA->>DB: SELECT ... FROM admins WHERE admin_cod = %s
    DB-->>MA: fila | None
    MA-->>F: Admin | None

    alt Es estudiante
        alt password válido y active = 1
            F->>FL: login_user(user)
            F-->>B: 302 → /home
        else inválido o inactivo
            F-->>B: 200 login.html + flash
        end
    else Es administrador
        alt password válido
            F->>FL: login_user(admin)
            F-->>B: 302 → /admin
        else
            F-->>B: 200 login.html + flash "Contraseña incorrecta"
        end
    else No existe
        F-->>B: 200 login.html + flash "Usurario no encontrado"
    end
```

### 4.2 Consulta al chatbot y resaltado en el mapa

```mermaid
sequenceDiagram
    autonumber
    actor E as Estudiante
    participant CJ as chatbot.js
    participant MJ as mapa.js (Leaflet)
    participant F as Flask /chatbot
    participant IDX as all_embeddings (memoria)
    participant OAI as OpenAI API
    participant DB as MySQL

    E->>CJ: Escribe pregunta + Enter
    CJ->>CJ: Pinta mensaje del usuario
    CJ->>F: POST /chatbot {message} + X-CSRFToken
    alt índice vacío
        F-->>CJ: {reply: "El chatbot aún no está listo..."}
    else índice con datos
        F->>OAI: Embedding.create(pregunta, ada-002)
        OAI-->>F: vector[1536]
        F->>IDX: similitud coseno contra cada fragmento
        IDX-->>F: top-5 (similitud, fragmento, office_id)
        F->>F: office_id = top-1.office_id
        F->>DB: SELECT * FROM offices WHERE office_id = %s
        DB-->>F: datos de la oficina
        alt la pregunta es un saludo
            F->>F: "Hola, ¿en qué puedo ayudarte?"
        else
            F->>OAI: ChatCompletion.create(gpt-3.5-turbo, prompt con contexto)
            OAI-->>F: respuesta
        end
        F-->>CJ: {reply, office_id}
    end
    CJ->>CJ: Pinta respuesta del bot
    opt office_id presente
        CJ->>MJ: highlightOffice(office_id)
        MJ->>MJ: Restablece iconos, resalta marcador
        MJ->>MJ: setView(zoom 18) + openPopup()
    end
```

### 4.3 Entrenamiento del chatbot (carga de PDF)

```mermaid
sequenceDiagram
    autonumber
    actor C as Coordinador
    participant B as Navegador
    participant F as Flask /upload_pdf
    participant FS as Disco
    participant PDF as PyPDF2
    participant TK as tiktoken
    participant OAI as OpenAI API
    participant IDX as all_embeddings

    C->>B: Selecciona PDF y pulsa "Subir PDF"
    B->>F: POST multipart (pdf_file, csrf_token)
    F->>FS: Guarda uploads/<nombre>.pdf
    F->>PDF: extract_text_from_pdf()
    PDF-->>F: texto
    alt texto vacío
        F-->>B: flash "El PDF no contiene texto..." + redirect
    else
        F->>TK: split_text(texto, 500)
        TK-->>F: N fragmentos
        loop por cada fragmento
            F->>OAI: Embedding.create(fragmento)
            OAI-->>F: vector
        end
        F->>FS: pickle.dump → embeddings/embeddings_<office_id>.pkl
        F->>IDX: clear()
        loop por cada .pkl en embeddings/
            F->>FS: pickle.load
            F->>IDX: extend(registros)
        end
        F-->>B: 302 → /admin + flash de éxito
    end
```

### 4.4 Carga del mapa del campus

```mermaid
sequenceDiagram
    autonumber
    actor U as Usuario
    participant B as Navegador
    participant F as Flask /home
    participant DB as MySQL
    participant OSM as OpenStreetMap

    U->>B: GET /home
    B->>F: GET /home (cookie de sesión)
    F->>DB: SELECT * FROM campus C JOIN offices O ... WHERE campus_name = current_user.campus
    DB-->>F: filas campus+oficina
    alt sin oficinas en el campus
        F-->>B: 404 "Campus not found"
    else
        F->>F: json.dumps(oficinas), json.dumps(GeoJSON)
        F-->>B: home.html con variables JS embebidas
        B->>B: L.map(campusLat, campusLon, 17)
        B->>OSM: GET teselas {z}/{x}/{y}.png
        OSM-->>B: imágenes
        B->>B: Dibuja polígono GeoJSON y marcadores
    end
```

### 4.5 Operación CRUD genérica (ej. alta de oficina)

```mermaid
sequenceDiagram
    autonumber
    actor S as Super admin
    participant B as Navegador
    participant F as Flask
    participant DB as MySQL

    S->>B: GET /office_View
    B->>F: GET /office_View
    F->>DB: SELECT offices LEFT JOIN admins
    F->>DB: SELECT campus
    F-->>B: office_view.html (tabla + modales)
    S->>B: Llena modal "Agregar oficina"
    B->>F: POST /office_Add (campus, nombre, lat, lon, carrera)
    F->>DB: INSERT INTO offices (...)
    F->>DB: COMMIT
    F-->>B: 302 → /office_View + flash "Oficina creada con exito."
```

---

## 5. Diagramas de actividad

### 5.1 Autenticación

```mermaid
flowchart TD
    A((Inicio)) --> B[/Ingresar código y contraseña/]
    B --> C[Buscar código en users]
    C --> D[Buscar código en admins]
    D --> E{¿Existe en users?}
    E -- Sí --> F{¿Contraseña válida<br/>y active = 1?}
    F -- Sí --> G[login_user] --> H[Ir a /home] --> Z((Fin))
    F -- No --> X[Mostrar error] --> B
    E -- No --> I{¿Existe en admins?}
    I -- Sí --> J{¿Contraseña válida?}
    J -- Sí --> K[login_user] --> L[Ir a /admin]
    L --> M{admin_priv = 1?}
    M -- Sí --> N[Panel super admin<br/>admin_rec.html] --> Z
    M -- No --> O[Panel coordinador<br/>admin.html] --> Z
    J -- No --> X
    I -- No --> Y[Usuario no encontrado] --> B
```

### 5.2 Ingesta de PDF (pipeline RAG offline)

```mermaid
flowchart TD
    S((Inicio)) --> A[/Recibir PDF/]
    A --> B{¿Hay archivo?}
    B -- No --> E1[Flash: sube un PDF] --> F((Fin))
    B -- Sí --> C[Guardar en uploads/]
    C --> D[Extraer texto de cada página]
    D --> G{¿Texto vacío?}
    G -- Sí --> E2[Flash: PDF sin texto] --> F
    G -- No --> H[Dividir en oraciones por '. ']
    H --> I{¿Oración > 500 tokens?}
    I -- Sí --> J[Dividir por palabras<br/>en sub-fragmentos ≤ 500]
    I -- No --> K{¿Cabe en el fragmento actual?}
    K -- Sí --> L[Agregar al fragmento]
    K -- No --> M[Cerrar fragmento y abrir uno nuevo]
    J --> N{¿Más oraciones?}
    L --> N
    M --> N
    N -- Sí --> I
    N -- No --> O[Generar embedding por fragmento]
    O --> P[Guardar embeddings_office_id.pkl]
    P --> Q[Recargar todos los .pkl en memoria]
    Q --> R[Flash: éxito] --> F
```

### 5.3 Respuesta del chatbot

```mermaid
flowchart TD
    S((Inicio)) --> A[/Pregunta del usuario/]
    A --> B{¿Índice vacío?}
    B -- Sí --> R1[Responder: chatbot no listo] --> Z((Fin))
    B -- No --> C[Embedding de la pregunta]
    C --> D[Similitud coseno con cada fragmento]
    D --> E[Ordenar y tomar top-5]
    E --> F[Concatenar textos como contexto]
    F --> G[office_id = fragmento más similar]
    G --> H[Consultar datos de la oficina]
    H --> I{¿Es saludo?}
    I -- Sí --> J[Respuesta fija]
    I -- No --> K[Llamar a gpt-3.5-turbo]
    K --> L{¿Error?}
    L -- Sí --> M[Mensaje de disculpa]
    L -- No --> N[Respuesta generada]
    J & M & N --> O[/JSON reply + office_id/] --> Z
```

---

## 6. Diagramas de estados

### 6.1 Sesión de usuario

```mermaid
stateDiagram-v2
    [*] --> Anónimo
    Anónimo --> Autenticando : POST /login
    Autenticando --> Anónimo : credenciales inválidas / inactivo
    Autenticando --> SesiónEstudiante : User válido
    Autenticando --> SesiónAdmin : Admin válido
    state SesiónAdmin {
        [*] --> Coordinador : admin_priv = 0
        [*] --> SuperAdmin : admin_priv = 1
    }
    SesiónEstudiante --> Anónimo : GET /logout
    SesiónAdmin --> Anónimo : GET /logout
    SesiónEstudiante --> Anónimo : cookie expirada / 401
    SesiónAdmin --> Anónimo : cookie expirada / 401
```

### 6.2 Conocimiento de una oficina en el chatbot

```mermaid
stateDiagram-v2
    [*] --> SinConocimiento : oficina creada
    SinConocimiento --> Procesando : coordinador sube PDF
    Procesando --> SinConocimiento : PDF sin texto
    Procesando --> Entrenada : .pkl guardado y recargado
    Entrenada --> Procesando : coordinador sube PDF nuevo
    Entrenada --> Huérfana : oficina eliminada (el .pkl persiste)
    Huérfana --> [*] : borrado manual del .pkl
```

### 6.3 Ventana del chatbot (cliente)

```mermaid
stateDiagram-v2
    [*] --> Cerrada
    Cerrada --> Abierta : clic en icono
    Abierta --> Cerrada : clic en ×
    state Abierta {
        [*] --> EnEspera
        EnEspera --> Enviando : Enter / Enviar con texto
        Enviando --> MostrandoRespuesta : 200 OK
        Enviando --> MostrandoError : error HTTP / red
        MostrandoRespuesta --> EnEspera : resalta oficina (si aplica)
        MostrandoError --> EnEspera
    }
```

---

## 7. Diagrama de componentes

```mermaid
flowchart LR
    subgraph Cliente["«component» Cliente web"]
        T[Plantillas Jinja2]
        MJS[mapa.js]
        CJS[chatbot.js]
        LEAF[Leaflet]
        BS[Bootstrap]
    end
    subgraph Servidor["«component» Servidor Flask"]
        R[Enrutador / vistas]
        AU[Autenticación<br/>Flask-Login]
        CS[CSRFProtect]
        RAG[Motor RAG]
        DAO[Modelos de acceso a datos]
    end
    DB[("«component» MySQL")]
    VEC[("«artifact» *.pkl")]
    OAI[["«component» OpenAI"]]

    CJS -- "IChat: POST /chatbot JSON" --> R
    CJS -- "highlightOffice()" --> MJS
    MJS --> LEAF
    T -- "IForm: POST formularios" --> R
    R --> AU
    R --> CS
    R --> RAG
    R --> DAO
    AU --> DAO
    DAO -- "SQL" --> DB
    RAG -- "pickle" --> VEC
    RAG -- "HTTPS" --> OAI
```

---

## 8. Diagrama de despliegue

```mermaid
flowchart TB
    subgraph N1["«device» PC / Smartphone"]
        subgraph N1a["«execution environment» Navegador"]
            A1["«artifact» HTML + JS + CSS"]
        end
    end

    subgraph N2["«device» Servidor de aplicación"]
        subgraph N2a["«execution environment» Python 3.12 + venv"]
            A2["«artifact» src/app.py"]
            A3["«artifact» requirements.txt"]
        end
        A4["«artifact» embeddings/*.pkl"]
        A5["«artifact» uploads/*.pdf"]
        A6["«artifact» .env / config.py"]
    end

    subgraph N3["«device» Servidor de BD"]
        subgraph N3a["«execution environment» MySQL 8"]
            A7["«schema» lion_solver"]
        end
    end

    subgraph N4["«external» OpenAI Cloud"]
        A8["«service» /v1/embeddings<br/>/v1/chat/completions"]
    end

    N1a -- "HTTPS" --> N2a
    N2a -- "TCP 3306" --> N3a
    N2a -- "HTTPS 443" --> N4
```
