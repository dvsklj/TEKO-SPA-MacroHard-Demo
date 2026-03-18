"""MacroHard Application Factory"""
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)


def create_app(config_name='default'):
    """Application factory pattern for creating Flask app"""
    from config import config
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Ensure the instance folder exists for the database
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    
    # Login configuration
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please sign in to access this page.'
    login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id):
        """Flask-Login user loader callback"""
        from app.models import User
        try:
            return User.query.get(int(user_id))
        except (TypeError, ValueError):
            return None
    
    # Security headers middleware
    @app.after_request
    def set_security_headers(response):
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        # XSS protection
        response.headers['X-XSS-Protection'] = '1; mode=block'
        # HSTS
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self';"
        )
        # Referrer policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response
    
    # Register blueprints
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp)
    
    from app.main import bp as main_bp
    app.register_blueprint(main_bp)
    
    from app.api import bp as api_bp
    app.register_blueprint(api_bp)
    
    # Create database tables and seed data
    with app.app_context():
        db.create_all()
        _create_default_admin()
        
        # Seed demo data if DEMO_MODE is enabled
        if os.environ.get('DEMO_MODE', 'false').lower() == 'true':
            _seed_demo_data()
    
    return app


def _create_default_admin():
    """Create default admin user if not exists"""
    from app.models import User
    from sqlalchemy.exc import IntegrityError
    
    if not User.query.filter_by(email='admin@macrohard.local').first():
        admin = User(
            email='admin@macrohard.local',
            username='admin',
            is_admin=True,
            email_verified=True
        )
        admin.set_password('ChangeMe123!')
        db.session.add(admin)
        try:
            db.session.commit()
            print("[MacroHard] Default admin created: admin@macrohard.local / ChangeMe123!")
        except IntegrityError:
            # Multiple workers may race on first boot; ignore duplicate admin creation.
            db.session.rollback()


def _seed_demo_data():
    """Seed demo data for demonstration purposes"""
    from app.models import User, Project, Vulnerability, Analysis
    from datetime import datetime, timedelta
    import random
    
    # Check if demo user already exists
    demo_user = User.query.filter_by(email='demo@macrohard.local').first()
    if demo_user:
        print("[MacroHard] Demo data already exists, skipping...")
        return
    
    print("[MacroHard] Seeding demo data...")
    
    # Create demo user
    demo_user = User(
        email='demo@macrohard.local',
        username='demo',
        is_admin=False,
        email_verified=True,
        created_at=datetime.utcnow() - timedelta(days=30)
    )
    demo_user.set_password('demo123!')
    db.session.add(demo_user)
    db.session.commit()
    
    # Sample projects with vulnerabilities
    projects_data = [
        {
            'name': 'E-Commerce API',
            'repo_url': 'https://github.com/demo/ecommerce-api',
            'vulnerabilities': [
                {
                    'title': 'SQL Injection in checkout endpoint',
                    'severity': 'critical',
                    'description': 'User-supplied order_id parameter is directly concatenated into SQL query without sanitization.\n\nVulnerable code:\nquery = f"SELECT * FROM orders WHERE id = {order_id}"\n\nThis allows attackers to extract sensitive data or modify orders.',
                    'recommendation': 'Use parameterized queries:\nquery = "SELECT * FROM orders WHERE id = %s"\ncursor.execute(query, (order_id,))',
                    'file_path': 'api/checkout.py',
                    'line_number': 142,
                    'rule_id': 'bandit.B608'
                },
                {
                    'title': 'Hardcoded payment gateway API key',
                    'severity': 'critical',
                    'description': 'Payment processor API key is hardcoded in the source code. This key grants access to payment operations and could be abused if exposed.',
                    'recommendation': 'Move API key to environment variable:\nSTRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")',
                    'file_path': 'config/payments.py',
                    'line_number': 8,
                    'rule_id': 'bandit.B105'
                },
                {
                    'title': 'Weak password hashing (MD5)',
                    'severity': 'high',
                    'description': 'User passwords are hashed using MD5 which is cryptographically broken and vulnerable to rainbow table attacks.',
                    'recommendation': 'Use bcrypt for password hashing:\nimport bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
                    'file_path': 'auth/password.py',
                    'line_number': 23,
                    'rule_id': 'bandit.B303'
                },
                {
                    'title': 'Missing rate limiting on login',
                    'severity': 'medium',
                    'description': 'Login endpoint does not implement rate limiting, making it vulnerable to brute force attacks.',
                    'recommendation': 'Implement rate limiting using Flask-Limiter or similar library.',
                    'file_path': 'auth/views.py',
                    'line_number': 45,
                    'rule_id': 'semgrep.rate-limit-missing'
                }
            ]
        },
        {
            'name': 'User Management Service',
            'repo_url': 'https://github.com/demo/user-service',
            'vulnerabilities': [
                {
                    'title': 'Debug mode enabled',
                    'severity': 'high',
                    'description': 'Flask debug mode is enabled in production configuration, exposing stack traces and potentially sensitive information.',
                    'recommendation': 'Set DEBUG = False in production config.',
                    'file_path': 'app.py',
                    'line_number': 12,
                    'rule_id': 'bandit.B201'
                },
                {
                    'title': 'Insecure deserialization',
                    'severity': 'high',
                    'description': 'User session data is deserialized using pickle which can execute arbitrary code if the session cookie is tampered with.',
                    'recommendation': 'Use JSON for session serialization or sign cookies with a secret key.',
                    'file_path': 'session/manager.py',
                    'line_number': 34,
                    'rule_id': 'bandit.B301'
                },
                {
                    'title': 'Verbose error messages',
                    'severity': 'low',
                    'description': 'Error handlers return full stack traces to clients, potentially exposing internal implementation details.',
                    'recommendation': 'Return generic error messages to clients and log details server-side.',
                    'file_path': 'handlers/errors.py',
                    'line_number': 18,
                    'rule_id': 'bandit.B110'
                }
            ]
        },
        {
            'name': 'Analytics Dashboard',
            'repo_url': None,
            'vulnerabilities': [
                {
                    'title': 'Use of eval() with user input',
                    'severity': 'critical',
                    'description': 'User-supplied filter expressions are passed directly to eval(), allowing arbitrary code execution.',
                    'recommendation': 'Use a safe expression parser or whitelist allowed operations.',
                    'file_path': 'filters/parser.py',
                    'line_number': 56,
                    'rule_id': 'bandit.B307'
                },
                {
                    'title': 'Missing CSRF protection',
                    'severity': 'medium',
                    'description': 'State-changing operations do not validate CSRF tokens, allowing attackers to perform actions on behalf of authenticated users.',
                    'recommendation': 'Add CSRF token validation to all POST/PUT/DELETE endpoints.',
                    'file_path': 'api/reports.py',
                    'line_number': 89,
                    'rule_id': 'semgrep.csrf-missing'
                },
                {
                    'title': 'Unvalidated redirect',
                    'severity': 'medium',
                    'description': 'The next parameter in login redirect is not validated, allowing open redirects to malicious sites.',
                    'recommendation': 'Validate redirect URLs against a whitelist or use relative paths only.',
                    'file_path': 'auth/login.py',
                    'line_number': 67,
                    'rule_id': 'bandit.B608'
                }
            ]
        },
        {
            'name': 'Inventory System',
            'repo_url': 'https://github.com/demo/inventory-system',
            'vulnerabilities': [
                {
                    'title': 'JWT secret exposed in config',
                    'severity': 'critical',
                    'description': 'JWT signing secret is hardcoded in configuration file, allowing attackers to forge authentication tokens.',
                    'recommendation': 'Move JWT secret to environment variable and rotate immediately.',
                    'file_path': 'config/auth.py',
                    'line_number': 5,
                    'rule_id': 'bandit.B105'
                },
                {
                    'title': 'Path traversal vulnerability',
                    'severity': 'high',
                    'description': 'File upload functionality does not validate file paths, allowing attackers to write files outside intended directories.',
                    'recommendation': 'Validate and sanitize all file paths, use uuid for filenames.',
                    'file_path': 'uploads/handler.py',
                    'line_number': 42,
                    'rule_id': 'semgrep.path-traversal'
                }
            ]
        }
    ]
    
    for project_data in projects_data:
        project = Project(
            name=project_data['name'],
            repo_url=project_data['repo_url'],
            user_id=demo_user.id,
            created_at=datetime.utcnow() - timedelta(days=random.randint(1, 28))
        )
        db.session.add(project)
        db.session.commit()
        
        # Create analysis record
        analysis = Analysis(
            project_id=project.id,
            status='completed',
            started_at=project.created_at,
            completed_at=project.created_at,
            findings_count=len(project_data['vulnerabilities']),
            triggered_by=demo_user.id
        )
        db.session.add(analysis)
        
        # Create vulnerabilities
        for vuln_data in project_data['vulnerabilities']:
            vuln = Vulnerability(
                project_id=project.id,
                title=vuln_data['title'],
                severity=vuln_data['severity'],
                file_path=vuln_data.get('file_path'),
                line_number=vuln_data.get('line_number'),
                rule_id=vuln_data['rule_id'],
                status='open',
                created_at=project.created_at + timedelta(hours=random.randint(1, 24))
            )
            vuln.description = vuln_data['description']
            vuln.recommendation = vuln_data['recommendation']
            db.session.add(vuln)
        
        db.session.commit()
    
    print(f"[MacroHard] Demo data created: demo@macrohard.local / demo123!")
    print(f"[MacroHard] {len(projects_data)} projects with sample vulnerabilities")
