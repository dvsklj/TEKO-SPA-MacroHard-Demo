"""Configuration for MacroHard - Security Analysis Platform"""
import os
from cryptography.fernet import Fernet


class Config:
    """Base configuration with security-focused defaults"""
    
    # Application
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable must be set")
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///data/macrohard.db')
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
