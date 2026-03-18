"""Configuration for MacroHard - Security Analysis Platform"""
import os
from cryptography.fernet import Fernet


def _normalize_database_url(raw_url: str, basedir: str) -> str:
    """Normalize sqlite relative paths to absolute to avoid cwd-related issues."""
    if raw_url.startswith("sqlite:///") and not raw_url.startswith("sqlite:////"):
        rel_path = raw_url.replace("sqlite:///", "", 1)
        abs_path = os.path.abspath(os.path.join(basedir, rel_path))
        return f"sqlite:////{abs_path}"
    return raw_url


class Config:
    """Base configuration with security-focused defaults"""
    
    # Application
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable must be set")
    
    # Database
    basedir = os.path.abspath(os.path.dirname(__file__))
    raw_db_url = os.environ.get('DATABASE_URL') or 'sqlite:///instance/macrohard.db'
    SQLALCHEMY_DATABASE_URI = _normalize_database_url(raw_db_url, basedir)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security - Encryption at Rest
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    if not ENCRYPTION_KEY:
        raise ValueError("ENCRYPTION_KEY environment variable must be set")
    
    # Password Hashing
    BCRYPT_LOG_ROUNDS = 12
    
    # Session Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    
    # Rate Limiting
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_STRATEGY = "fixed-window"
    
    # File Uploads
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # Analysis Settings
    ANALYSIS_TIMEOUT = 300  # 5 minutes max for initial analysis
    

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = False
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development
    

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
