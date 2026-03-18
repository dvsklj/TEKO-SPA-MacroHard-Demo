"""Database Models with Encryption at Rest"""
from datetime import datetime
from flask_login import UserMixin
from cryptography.fernet import Fernet
from app import db, bcrypt
from flask import current_app


class User(UserMixin, db.Model):
    """User model with secure password hashing"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    projects = db.relationship('Project', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash password using bcrypt"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Verify password against hash"""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def __repr__(self):
        return f'<User {self.username}>'


class Project(db.Model):
    """Project model for code repositories"""
    __tablename__ = 'projects'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    repo_url = db.Column(db.String(500))
    repo_provider = db.Column(db.String(20))  # github, gitlab, etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='project', 
                                     lazy='dynamic', cascade='all, delete-orphan')
    analyses = db.relationship('Analysis', backref='project',
                              lazy='dynamic', cascade='all, delete-orphan')
    
    @property
    def critical_count(self):
        return self.vulnerabilities.filter_by(severity='critical', status='open').count()
    
    @property
    def high_count(self):
        return self.vulnerabilities.filter_by(severity='high', status='open').count()
    
    @property
    def medium_count(self):
        return self.vulnerabilities.filter_by(severity='medium', status='open').count()
    
    @property
    def low_count(self):
        return self.vulnerabilities.filter_by(severity='low', status='open').count()
    
    @property
    def total_open(self):
        return self.vulnerabilities.filter_by(status='open').count()
    
    def __repr__(self):
        return f'<Project {self.name}>'


class Vulnerability(db.Model):
    """Vulnerability model with encrypted descriptions"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False, index=True)  # critical, high, medium, low
    description_encrypted = db.Column(db.Text, nullable=False)
    recommendation_encrypted = db.Column(db.Text)
    file_path = db.Column(db.String(500))
    line_number = db.Column(db.Integer)
    column_number = db.Column(db.Integer)
    rule_id = db.Column(db.String(100))  # e.g., bandit.B105
    status = db.Column(db.String(20), default='open')  # open, resolved, false_positive, ignored
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    def _get_fernet(self):
        """Get Fernet instance for encryption/decryption"""
        key = current_app.config['ENCRYPTION_KEY']
        if isinstance(key, str):
            key = key.encode()
        return Fernet(key)
    
    @property
    def description(self):
        """Decrypt description when accessed"""
        try:
            f = self._get_fernet()
            return f.decrypt(self.description_encrypted.encode()).decode('utf-8')
        except Exception:
            return "[Error decrypting data]"
    
    @description.setter
    def description(self, value):
        """Encrypt description before saving"""
        f = self._get_fernet()
        self.description_encrypted = f.encrypt(value.encode('utf-8')).decode('utf-8')
    
    @property
    def recommendation(self):
        """Decrypt recommendation when accessed"""
        if not self.recommendation_encrypted:
            return None
        try:
            f = self._get_fernet()
            return f.decrypt(self.recommendation_encrypted.encode()).decode('utf-8')
        except Exception:
            return None
    
    @recommendation.setter
    def recommendation(self, value):
        """Encrypt recommendation before saving"""
        if value:
            f = self._get_fernet()
            self.recommendation_encrypted = f.encrypt(value.encode('utf-8')).decode('utf-8')
    
    @property
    def severity_color(self):
        colors = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#ca8a04',
            'low': '#16a34a'
        }
        return colors.get(self.severity, '#6b7280')
    
    def __repr__(self):
        return f'<Vulnerability {self.title[:50]}>'


class Analysis(db.Model):
    """Analysis run record for tracking"""
    __tablename__ = 'analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    findings_count = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    triggered_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    @property
    def duration_seconds(self):
        if self.completed_at and self.started_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

class AuditLog(db.Model):
    """Audit log for security events"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(50), nullable=False)  # login, logout, create_project, etc.
    resource_type = db.Column(db.String(50))  # project, vulnerability, user
    resource_id = db.Column(db.Integer)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)
