# MacroHard - Security Analysis Platform DEMO

**Hardening your Stack on a Macro Level**

MacroHard is a security analysis platform for software development projects. It automatically analyzes code for security vulnerabilities, tracks findings, and provides actionable insights. This is a rapidly prototyped demo for my TEKO SPA class and is NOT production ready. 

## Features

### Core Functionality
- **Self-Service Registration** - Users can register and start analyzing immediately
- **Project Management** - Create projects and link GitHub/GitLab repositories
- **Automated Security Analysis** - Scan code using Bandit (Python) and Semgrep (multi-language)
- **Vulnerability Tracking** - Track and manage security findings over time
- **CSV Export** - Export findings in OS-readable format for reporting

### Security Features
- **Encryption at Rest** - All vulnerability data encrypted with AES-256
- **Secure Authentication** - bcrypt password hashing (12 rounds)
- **CSRF Protection** - All forms protected against cross-site request forgery
- **Rate Limiting** - Prevent brute force attacks
- **Security Headers** - HSTS, CSP, X-Frame-Options, X-XSS-Protection
- **Audit Logging** - Track all security-relevant actions
- **Input Validation** - SQL injection & XSS protection
- **Secure Sessions** - HttpOnly, Secure, SameSite cookies

## Quick Start with Docker

### Option 1: Demo Mode

The demo mode comes pre-populated with sample projects and vulnerabilities:

```bash
# Clone the repository
git clone <repository-url>
cd macrohard

# Start in demo mode
docker-compose -f docker-compose.yml up -d --build

# Or with demo mode explicitly enabled:
DEMO_MODE=true docker-compose up -d --build

# Access the application
open http://localhost:5000
```

**Demo Credentials:**
- Email: `demo@macrohard.local`
- Password: `demo123!`

The demo includes 4 sample projects with realistic security vulnerabilities.

### Option 2: Production Mode -> Can be tested, but not to be used in production.

```bash
# Generate secure keys
./setup.sh

# Or manually:
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(64))")
export ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Start the application
docker-compose up -d --build

# Access the application
open http://localhost:5000
```

**Default Admin Credentials:**
- Email: `admin@macrohard.local`
- Password: `ChangeMe123!`

## Analyzing Real Code

### 1. Create a Project
1. Sign in to MacroHard
2. Click "New Project"
3. Enter project name and GitHub/GitLab repository URL (only public repos at the moment)
4. Click "Create Project"

### 2. Run Analysis
1. Navigate to your project
2. Click "Run Analysis"
3. The system will:
   - Clone the repository
   - Run Bandit (for Python code)
   - Run Semgrep (for multiple languages)
   - Store findings encrypted in the database

### 3. Review Findings
- View vulnerabilities by severity (Critical, High, Medium, Low)
- See file paths and line numbers
- Read descriptions and recommendations
- Update status (Open, Resolved, False Positive, Ignored)

### 4. Export Results
Click "Export" to download findings as CSV for reporting.

## Supported Languages & Tools

| Language | Tool | Coverage |
|----------|------|----------|
| Python | Bandit | Comprehensive |
| Python | Semgrep | Good |
| JavaScript | Semgrep | Good |
| TypeScript | Semgrep | Good |
| Java | Semgrep | Basic |
| Go | Semgrep | Basic |

## Architecture

### Technology Stack
- **Backend**: Flask (Python 3.11)
- **Database**: SQLite (default) / PostgreSQL (production)
- **Security**: bcrypt, Fernet (AES-256), CSRF tokens
- **Analysis**: Bandit, Semgrep, Git

### Project Structure
```
macrohard/
├── app/
│   ├── models.py            # Database models with encryption
│   ├── auth.py              # Authentication routes
│   ├── main.py              # Main application routes
│   ├── api.py               # API endpoints & webhooks
│   ├── analyzer.py          # Security analysis engine
│   ├── forms.py             # WTForms with validation
│   └── templates/           # HTML templates
├── config.py                # Configuration settings
├── wsgi.py                  # WSGI entry point
├── seed_demo.py             # Demo data seeder script
├── requirements.txt         # Python dependencies
├── Dockerfile               # Docker image with analysis tools
├── docker-compose.yml       # Docker Compose configuration
└── setup.sh                 # Setup script with key generation
```

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `SECRET_KEY` | Flask secret key (64+ chars) | Yes | - |
| `ENCRYPTION_KEY` | Fernet key for data encryption (32 bytes) | Yes | - |
| `DATABASE_URL` | Database connection string | No | `sqlite:///data/macrohard.db` |
| `FLASK_ENV` | Environment (development/production) | No | `production` |
| `DEMO_MODE` | Enable demo data on startup | No | `false` |

## Demo Data

The demo mode creates a user with pre-populated projects:

**Projects:**
1. **E-Commerce API** - Payment processing vulnerabilities
2. **User Management Service** - Authentication issues
3. **Analytics Dashboard** - Input validation problems
4. **Inventory System** - Configuration security flaws

**Vulnerability Types:**
- SQL Injection
- Hardcoded secrets
- Weak cryptography
- Debug mode exposure
- Missing CSRF protection
- Path traversal
- Insecure deserialization

## API Endpoints

### Webhooks
- `POST /api/v1/webhook/github` - GitHub push event webhook

### Analysis
- `GET /api/v1/analysis/<id>/status` - Get analysis status
- `GET /api/v1/projects/<id>/stats` - Get project vulnerability stats

## Development

### Running Tests
```bash
pip install pytest pytest-cov
pytest
```

### Adding New Analyzers

Edit `app/analyzer.py` to add new security analysis tools:

```python
def analyze_with_custom_tool(self, repo_path, project):
    """Run custom security analyzer"""
    findings = []
    # Run your tool
    # Parse results
    # Return standardized findings
    return findings
```

### Manual Demo Data Seeding

```bash
# After starting the container
python seed_demo.py
```

## Security Considerations

### Production Deployment Checklist

- [ ] Change default admin password
- [ ] Generate new SECRET_KEY and ENCRYPTION_KEY
- [ ] Use PostgreSQL instead of SQLite
- [ ] Enable HTTPS with valid SSL certificates
- [ ] Configure firewall (only expose 443)
- [ ] Set up Redis for distributed rate limiting
- [ ] Configure regular backups
- [ ] Enable audit logging
- [ ] Set up monitoring and alerting

### Key Rotation

To rotate encryption keys:
1. Export all data as CSV
2. Generate new ENCRYPTION_KEY
3. Restart application
4. Re-import data

## Troubleshooting

### Analysis Timeout
If analysis times out on large repositories:
- The repository may be too large
- Try analyzing specific directories
- Increase timeout in `config.py`

### Bandit/Semgrep Not Found
These tools are included in the Docker image. If running manually:
```bash
pip install bandit semgrep
```

### Permission Errors
Ensure the data directory is writable:
```bash
chmod 755 data
```

## License

MIT License - See LICENSE file for details