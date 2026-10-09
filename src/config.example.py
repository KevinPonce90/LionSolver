# Plantilla de configuración. Copia este archivo como src/config.py (no se versiona)
# y ajusta los valores para tu entorno.
import os

from dotenv import load_dotenv

# app.py importa este módulo antes de llamar a load_dotenv(), así que se carga aquí.
load_dotenv()


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'cambia-esta-clave')
    MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
    MYSQL_PORT = int(os.getenv('MYSQL_PORT', 3306))
    MYSQL_USER = os.getenv('MYSQL_USER', 'lion_app')
    MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', '')
    MYSQL_DB = os.getenv('MYSQL_DB', 'lion_solver')


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
}
