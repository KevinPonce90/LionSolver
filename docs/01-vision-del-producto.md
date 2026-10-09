# 01 · Visión del producto

## 1. Declaración de visión

> **Para** los estudiantes de un centro universitario **que** no saben a qué oficina
> acudir para resolver un trámite ni dónde se encuentra físicamente, **Lion Solver** es
> una aplicación web de orientación **que** responde sus dudas en lenguaje natural y les
> señala en el mapa del campus la oficina correcta. **A diferencia de** los directorios
> estáticos, páginas web dispersas y la consulta presencial de oficina en oficina,
> **nuestro producto** concentra la información oficial de cada dependencia —cargada y
> mantenida por la propia oficina— y la combina con geolocalización.

## 2. Problema

| Aspecto | Descripción |
|---|---|
| Problema | Los estudiantes desconocen qué oficina atiende cada trámite (servicio social, titulación, becas, coordinaciones de carrera…) y dónde está dentro de un campus extenso. |
| Afecta a | Estudiantes (especialmente de nuevo ingreso), personal de las oficinas que recibe consultas mal dirigidas. |
| Impacto | Tiempo perdido recorriendo el campus, filas en oficinas equivocadas, trámites fuera de plazo, carga de trabajo repetitiva para el personal. |
| Solución exitosa | Un único punto de consulta que responde *qué* hacer, *dónde* hacerlo y *cómo contactar* a la oficina. |

## 3. Objetivos del producto

| ID | Objetivo | Indicador de éxito (KPI propuesto) |
|---|---|---|
| OBJ-1 | Reducir el tiempo que tarda un estudiante en identificar la oficina correcta | ≥ 80 % de las preguntas de prueba se asocian a la oficina correcta |
| OBJ-2 | Ubicar físicamente cada oficina en el campus | 100 % de las oficinas registradas tienen coordenadas válidas dentro del polígono del campus |
| OBJ-3 | Que cada oficina mantenga su propia información sin depender de TI | Una oficina puede actualizar datos y PDF en < 5 minutos |
| OBJ-4 | Escalar a varios campus | Alta de un campus nuevo solo con datos administrativos (GeoJSON + oficinas), sin cambios de código |

## 4. Alcance

### 4.1 Dentro del alcance (versión 4.1)

- Autenticación con código y contraseña para estudiantes y administradores.
- Mapa interactivo del campus del usuario (polígono GeoJSON + marcadores de oficinas).
- Chatbot con recuperación aumentada (RAG) sobre los PDF cargados por las oficinas.
- Resaltado automático en el mapa de la oficina asociada a la respuesta.
- Panel de coordinador de oficina: editar datos de contacto y cargar PDF.
- Panel de super administrador: CRUD de campus, oficinas y administradores.

### 4.2 Fuera del alcance

- Registro autónomo de estudiantes (se asume alta directa en la base de datos o integración futura con el sistema escolar).
- Navegación paso a paso (rutas a pie) dentro del campus.
- Historial de conversaciones del chatbot.
- Aplicación móvil nativa.
- Integración con sistemas de trámites o citas.

## 5. Stakeholders y usuarios

| Stakeholder | Rol en el sistema | Interés principal | Nivel de influencia |
|---|---|---|---|
| Estudiante | `User` | Resolver dudas y encontrar oficinas rápido | Alto (usuario final) |
| Coordinador / responsable de oficina | `Admin` regular (`admin_priv = 0`) | Publicar información correcta de su oficina | Medio |
| Super administrador | `Admin` super (`admin_priv = 1`) | Mantener el catálogo de campus, oficinas y cuentas | Alto |
| Dirección del centro universitario | — (patrocinador) | Mejorar la atención estudiantil | Alto |
| Equipo de desarrollo | — | Mantenibilidad, costos de API | Medio |

## 6. Personas

**Ana, 18 años — estudiante de nuevo ingreso.** Usa el celular para todo. No conoce el
campus y no sabe que "Servicio Social" tiene una unidad propia. Quiere una respuesta en
una frase y ver en el mapa a dónde caminar.

**Luis, 42 años — coordinador de la Unidad de Servicio Social.** Recibe todos los días
las mismas preguntas. Tiene sus lineamientos en un PDF. Quiere subir ese PDF una vez y
que el sistema conteste por él.

**Marta, 35 años — administradora de sistemas del centro.** Da de alta campus, oficinas
y coordinadores. Necesita formularios simples y control sobre quién puede editar qué.

## 7. Supuestos y restricciones

| Tipo | Descripción |
|---|---|
| Supuesto | Los estudiantes ya existen en la tabla `users` con su campus asignado. |
| Supuesto | Cada administrador está asociado a exactamente una oficina y un campus. |
| Supuesto | Los PDF de las oficinas contienen texto extraíble (no son imágenes escaneadas). |
| Restricción | Dependencia de un servicio externo de pago (OpenAI) para embeddings y respuestas. |
| Restricción | El mapa base depende de las teselas públicas de OpenStreetMap. |
| Restricción | El índice vectorial se mantiene en memoria del proceso (un solo proceso de servidor). |

## 8. Glosario

| Término | Definición |
|---|---|
| **Campus** | Centro universitario con un polígono geográfico (GeoJSON) y un punto central (lat/lon). Su clave es el nombre. |
| **Oficina** | Dependencia física dentro de un campus, con coordenadas, carrera/área, contacto y horario. |
| **Código** | Identificador numérico institucional usado como usuario para iniciar sesión. |
| **Coordinador** | Administrador regular responsable de una oficina. |
| **Super administrador** | Administrador con `admin_priv = 1`; gestiona campus, oficinas y cuentas. |
| **Embedding** | Vector numérico (1 536 dimensiones con `text-embedding-ada-002`) que representa el significado de un texto. |
| **Fragmento (chunk)** | Porción del texto de un PDF de máximo 500 tokens. |
| **RAG** | *Retrieval-Augmented Generation*: se recuperan fragmentos relevantes y se pasan como contexto al modelo generativo. |
| **GeoJSON** | Formato estándar (RFC 7946) para representar geometrías geográficas. |
| **Similitud coseno** | Medida de cercanía entre dos vectores, usada para elegir los fragmentos más relevantes. |
