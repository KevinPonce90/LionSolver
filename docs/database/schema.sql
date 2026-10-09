-- =====================================================================
--  Lion Solver — Esquema de base de datos (MySQL 8 / MariaDB 10.5+)
-- ---------------------------------------------------------------------
--  IMPORTANTE: este esquema se RECONSTRUYÓ a partir de las consultas
--  SQL de src/app.py y src/models/*.py (versión 4.1). El repositorio
--  original no incluía el DDL. Revise tipos y longitudes contra la base
--  de datos productiva antes de usarlo para migrar datos reales.
-- =====================================================================

CREATE DATABASE IF NOT EXISTS lion_solver
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE lion_solver;

-- ---------------------------------------------------------------------
-- campus: centro universitario con su polígono GeoJSON
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS campus (
    campus_name    VARCHAR(100)   NOT NULL,
    campus_coords  JSON           NOT NULL COMMENT 'GeoJSON FeatureCollection del perímetro',
    campus_lat     DECIMAL(10, 7) NOT NULL COMMENT 'Latitud del centro del mapa',
    campus_lon     DECIMAL(10, 7) NOT NULL COMMENT 'Longitud del centro del mapa',
    CONSTRAINT pk_campus PRIMARY KEY (campus_name)
) ENGINE = InnoDB;

-- ---------------------------------------------------------------------
-- offices: oficinas/dependencias dentro de un campus
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS offices (
    office_id      INT            NOT NULL AUTO_INCREMENT,
    office_campus  VARCHAR(100)   NOT NULL,
    office_name    VARCHAR(150)   NOT NULL,
    office_desc    TEXT               NULL,
    office_phone   VARCHAR(50)        NULL,
    office_hours   VARCHAR(100)       NULL,
    office_lat     DECIMAL(10, 7) NOT NULL,
    office_lon     DECIMAL(10, 7) NOT NULL,
    office_career  VARCHAR(150)       NULL COMMENT 'Carrera o área que atiende',
    CONSTRAINT pk_offices PRIMARY KEY (office_id),
    CONSTRAINT fk_offices_campus FOREIGN KEY (office_campus)
        REFERENCES campus (campus_name)
        ON UPDATE CASCADE
        ON DELETE CASCADE
) ENGINE = InnoDB;

CREATE INDEX ix_offices_campus ON offices (office_campus);

-- ---------------------------------------------------------------------
-- admins: coordinadores de oficina (priv = 0) y super admins (priv = 1)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admins (
    admin_cod       INT           NOT NULL COMMENT 'Código institucional (usuario de login)',
    admin_password  VARCHAR(255)  NOT NULL COMMENT 'Hash Werkzeug (scrypt/pbkdf2)',
    admin_campus    VARCHAR(100)  NOT NULL,
    admin_office    INT               NULL,
    admin_fullname  VARCHAR(150)  NOT NULL,
    admin_email     VARCHAR(150)  NOT NULL,
    admin_priv      TINYINT(1)    NOT NULL DEFAULT 0 COMMENT '0 = coordinador, 1 = super admin',
    CONSTRAINT pk_admins PRIMARY KEY (admin_cod),
    CONSTRAINT fk_admins_campus FOREIGN KEY (admin_campus)
        REFERENCES campus (campus_name)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,
    CONSTRAINT fk_admins_office FOREIGN KEY (admin_office)
        REFERENCES offices (office_id)
        ON UPDATE CASCADE
        ON DELETE SET NULL
) ENGINE = InnoDB;

-- ---------------------------------------------------------------------
-- users: estudiantes
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_cod       INT           NOT NULL COMMENT 'Código de estudiante (usuario de login)',
    user_password  VARCHAR(255)  NOT NULL COMMENT 'Hash Werkzeug',
    user_campus    VARCHAR(100)  NOT NULL,
    user_fullname  VARCHAR(150)  NOT NULL,
    user_email     VARCHAR(150)  NOT NULL,
    user_career    VARCHAR(150)      NULL,
    user_active    TINYINT(1)    NOT NULL DEFAULT 1 COMMENT '1 = puede iniciar sesión',
    CONSTRAINT pk_users PRIMARY KEY (user_cod),
    CONSTRAINT fk_users_campus FOREIGN KEY (user_campus)
        REFERENCES campus (campus_name)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
) ENGINE = InnoDB;

-- =====================================================================
--  Datos semilla (opcional)
--  Las contraseñas deben generarse con werkzeug.security.generate_password_hash:
--    python -c "from werkzeug.security import generate_password_hash as g; print(g('CambiaEsto123'))"
--  y pegar el resultado en lugar de <HASH>.
-- =====================================================================
-- INSERT INTO campus (campus_name, campus_coords, campus_lat, campus_lon)
-- VALUES ('CUCEI', '<contenido de src/static/json/cucei.json>', 20.6567, -103.3254);
--
-- INSERT INTO offices (office_campus, office_name, office_desc, office_phone, office_hours, office_lat, office_lon, office_career)
-- VALUES ('CUCEI', 'Unidad de Servicio Social', 'Trámites de servicio social', '33 0000 0000', 'L-V 9:00-15:00', 20.6560, -103.3260, 'General');
--
-- INSERT INTO admins (admin_cod, admin_password, admin_campus, admin_office, admin_fullname, admin_email, admin_priv)
-- VALUES (1000, '<HASH>', 'CUCEI', 1, 'Super Administrador', 'admin@example.com', 1);
--
-- INSERT INTO users (user_cod, user_password, user_campus, user_fullname, user_email, user_career, user_active)
-- VALUES (219000001, '<HASH>', 'CUCEI', 'Estudiante de Prueba', 'estudiante@example.com', 'INCO', 1);
