# 09 · Instalación y despliegue

## 1. Requisitos

| Componente | Versión | Notas |
|---|---|---|
| Python | 3.12 | Las dependencias fijadas en `requirements.txt` requieren ≥ 3.9 |
| MySQL / MariaDB | 8.0 / 10.5+ | Soporte para columnas `JSON` |
| Cabeceras de cliente MySQL | — | Necesarias para compilar `mysqlclient` |
| Cuenta de OpenAI | — | Clave de API con saldo |
| Git | 2.x | |

Dependencias del sistema para `mysqlclient`:

```bash
# Debian / Ubuntu
sudo apt-get install python3-dev default-libmysqlclient-dev build-essential pkg-config
# macOS (Homebrew)
brew install mysql-client pkg-config
# Windows: pip instala ruedas precompiladas de mysqlclient
```

## 2. Instalación local

```bash
# 1. Clonar
git clone https://github.com/KevinPonce90/LionSolver.git
cd LionSolver

# 2. Entorno virtual
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Dependencias
pip install -r requirements.txt
```

> `requirements.txt` está codificado en **UTF‑16**. `pip` lo lee sin problema; si una
> herramienta falla al leerlo, conviértalo con
> `iconv -f UTF-16 -t UTF-8 requirements.txt > requirements-utf8.txt`.

## 3. Configuración

### 3.1 Variables de entorno (`.env` en la raíz)

```bash
cp .env.example .env
```

| Variable | Obligatoria | Descripción |
|---|---|---|
| `OPENAI_API_KEY` | Sí | Clave de la API de OpenAI (leída por `src/app.py`) |
| `SECRET_KEY` | Sí | Clave de sesión/CSRF (leída por `src/config.example.py`) |
| `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DB` | Sí | Conexión a MySQL (leídas por `src/config.example.py`) |

Si ya tiene un `src/config.py` propio con los valores escritos directamente, solo
`OPENAI_API_KEY` es necesaria en `.env`.

### 3.2 Configuración de Flask (`src/config.py`)

`src/app.py` importa `from config import config` y usa `config['development']`. El
archivo **no se versiona** (está en `.gitignore`); parta de la plantilla:

```bash
cp src/config.example.py src/config.py
```

La plantilla lee los valores de `.env` y define dos perfiles, `development` y
`production`.

| Clave | Descripción |
|---|---|
| `SECRET_KEY` | Firma de la cookie de sesión y de los tokens CSRF. Use un valor aleatorio largo. |
| `DEBUG` | `True` solo en desarrollo. |
| `MYSQL_HOST`, `MYSQL_PORT` | Servidor de base de datos. |
| `MYSQL_USER`, `MYSQL_PASSWORD` | Credenciales. |
| `MYSQL_DB` | Nombre de la base (por defecto `lion_solver`). |

Genere una `SECRET_KEY`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 3.3 Base de datos

```bash
mysql -u root -p < docs/database/schema.sql
```

Cree un usuario de aplicación con privilegios mínimos:

```sql
CREATE USER 'lion_app'@'localhost' IDENTIFIED BY '<contraseña-segura>';
GRANT SELECT, INSERT, UPDATE, DELETE ON lion_solver.* TO 'lion_app'@'localhost';
FLUSH PRIVILEGES;
```

Cargue el primer campus y el primer super administrador (ver comentarios al final de
`schema.sql`). Para el GeoJSON de CUCEI use `src/static/json/cucei.json`.

Para generar el hash de una contraseña:

```bash
python -c "from werkzeug.security import generate_password_hash as g; print(g('CambiaEsto123'))"
```

## 4. Ejecución

Desde la **raíz del repositorio**:

```bash
python src/app.py
```

Abra <http://127.0.0.1:5000>.

> **No use `flask run`.** La configuración, `CSRFProtect` y los manejadores de errores se
> registran dentro de `if __name__ == '__main__':` en `src/app.py`; con `flask run` no se
> cargarían.

Al iniciar verá en consola cuántos embeddings se cargaron desde `embeddings/`.

## 5. Despliegue en producción

### 5.1 Lista de verificación previa

- [ ] `DEBUG = False` y `SECRET_KEY` aleatoria.
- [ ] Control de acceso por rol implementado (SEC-01).
- [ ] HTTPS obligatorio (terminado en el *reverse proxy*).
- [ ] `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = "Lax"`.
- [ ] `MAX_CONTENT_LENGTH` configurado (p. ej. 10 MB) para limitar el tamaño de PDFs.
- [ ] Usuario de base de datos con privilegios mínimos.
- [ ] Respaldos programados de MySQL, `embeddings/` y `uploads/`.
- [ ] Monitoreo de consumo y límite de gasto en la cuenta de OpenAI.

### 5.2 Servidor WSGI

El índice vectorial vive en la memoria del proceso; use **un solo worker** con varios
hilos (ver [04-arquitectura.md](04-arquitectura.md#3-vista-de-despliegue)). Como la
configuración se aplica en el bloque `__main__`, cree un punto de entrada WSGI que la
replique, por ejemplo `src/wsgi.py`:

```python
from app import app, csrf, status_401, status_404
from config import config

app.config.from_object(config['production'])
csrf.init_app(app)
app.register_error_handler(401, status_401)
app.register_error_handler(404, status_404)
```

```bash
pip install gunicorn
cd /ruta/LionSolver
gunicorn --chdir src --workers 1 --threads 8 --bind 127.0.0.1:8000 wsgi:app
```

> Con `--chdir src` el directorio de trabajo cambia a `src/`; las rutas relativas
> `embeddings/` y `uploads/` se resolverían ahí. Mueva esas carpetas o, mejor, conviértalas
> en rutas absolutas configurables (DT-09).

### 5.3 Nginx como *reverse proxy*

```nginx
server {
    listen 443 ssl http2;
    server_name lionsolver.ejemplo.edu.mx;

    ssl_certificate     /etc/letsencrypt/live/lionsolver/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/lionsolver/privkey.pem;

    client_max_body_size 10m;

    location /static/ {
        alias /ruta/LionSolver/src/static/;
        expires 7d;
    }

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }
}
```

### 5.4 Servicio systemd

```ini
[Unit]
Description=Lion Solver
After=network.target mysql.service

[Service]
User=lionsolver
WorkingDirectory=/ruta/LionSolver
EnvironmentFile=/ruta/LionSolver/.env
ExecStart=/ruta/LionSolver/.venv/bin/gunicorn --chdir src --workers 1 --threads 8 --bind 127.0.0.1:8000 wsgi:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## 6. Solución de problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| `ModuleNotFoundError: No module named 'config'` | Falta `src/config.py` | Copie `src/config.example.py` |
| `ModuleNotFoundError: No module named 'models'` | Se ejecuta con otro directorio en `sys.path` | Ejecute `python src/app.py` desde la raíz |
| `OperationalError (2002/1045)` | MySQL apagado o credenciales incorrectas | Revise `MYSQL_*` en `config.py` |
| Error al instalar `mysqlclient` | Faltan cabeceras de MySQL | Instale las dependencias del sistema (§1) |
| "El chatbot aún no está listo" | `embeddings/` vacío | Suba un PDF desde el panel de un coordinador |
| `openai.error.AuthenticationError` | `OPENAI_API_KEY` ausente o inválida | Revise `.env` |
| "Campus not found" (404) en `/home` | El campus del usuario no tiene oficinas | Registre al menos una oficina |
| `400 Bad Request: The CSRF token is missing` | Formulario sin `csrf_token` | Incluya `{{ csrf_token() }}` en el formulario |
| `TemplateNotFound: upload_pdf.html` | Se accedió a `GET /upload_pdf` o el PDF no tenía texto | Use el modal del panel; ver DT-07 |
