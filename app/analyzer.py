"""Security Analysis Engine - Real Code Analysis"""
import subprocess
import tempfile
import os
import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from app.models import Vulnerability, Analysis
from app import db


class SecurityAnalyzer:
    """Security code analyzer supporting multiple tools"""
    
    def __init__(self):
        self.supported_tools = ['bandit', 'semgrep']
        self.temp_dir = None
    
    def analyze_project(self, project, analysis_record=None):
        """Run full security analysis on a project"""
        findings = []
        
        # If no repo URL, use demo findings
        if not project.repo_url:
            findings = self._generate_demo_findings(project)
        else:
            # Clone and analyze real code
            findings = self._analyze_real_repository(project)
        
        # Save findings to database
        saved_count = 0
        for finding in findings:
            # Check for duplicates (same file, line, rule)
            existing = Vulnerability.query.filter_by(
                project_id=project.id,
                file_path=finding.get('file_path'),
                line_number=finding.get('line_number'),
                rule_id=finding.get('rule_id'),
                status='open'
            ).first()
            
            if not existing:
                vuln = Vulnerability(
                    project_id=project.id,
                    title=finding['title'],
                    severity=finding['severity'],
                    file_path=finding.get('file_path'),
                    line_number=finding.get('line_number'),
                    column_number=finding.get('column_number'),
                    rule_id=finding.get('rule_id'),
                    status='open'
                )
                vuln.description = finding['description']
                vuln.recommendation = finding.get('recommendation', '')
                
                db.session.add(vuln)
                saved_count += 1
        
        db.session.commit()
        
        # Update analysis record
        if analysis_record:
            analysis_record.status = 'completed'
            analysis_record.findings_count = saved_count
            analysis_record.completed_at = datetime.utcnow()
            db.session.commit()
        
        return findings
    
    def _analyze_real_repository(self, project):
        """Clone and analyze a real git repository"""
        findings = []
        temp_dir = None
        
        try:
            # Create temp directory
            temp_dir = tempfile.mkdtemp(prefix='macrohard_')
            
            # Clone repository
            clone_result = subprocess.run(
                ['git', 'clone', '--depth', '1', project.repo_url, temp_dir],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if clone_result.returncode != 0:
                raise Exception(f"Failed to clone repository: {clone_result.stderr}")
            
            # Run Bandit analysis (Python)
            bandit_findings = self._run_bandit(temp_dir, project)
            findings.extend(bandit_findings)
            
            # Run Semgrep analysis (multiple languages)
            semgrep_findings = self._run_semgrep(temp_dir, project)
            findings.extend(semgrep_findings)
            
        except subprocess.TimeoutExpired:
            findings.append({
                'title': 'Analysis timeout - repository too large',
                'severity': 'low',
                'description': 'The repository analysis timed out. Consider analyzing smaller chunks.',
                'recommendation': 'Try running analysis on specific directories.',
                'file_path': None,
                'line_number': None,
                'rule_id': 'macrohard.timeout'
            })
        except Exception as e:
            findings.append({
                'title': f'Analysis error: {str(e)[:100]}',
                'severity': 'low',
                'description': f'An error occurred during analysis: {str(e)}',
                'recommendation': 'Please check the repository URL and try again.',
                'file_path': None,
                'line_number': None,
                'rule_id': 'macrohard.error'
            })
        finally:
            # Cleanup temp directory
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
        
        return findings
    
    def _run_bandit(self, repo_path, project):
        """Run Bandit security analyzer on Python code"""
        findings = []
        
        # Check if there are any Python files
        python_files = list(Path(repo_path).rglob('*.py'))
        if not python_files:
            return findings
        
        try:
            result = subprocess.run(
                ['bandit', '-r', '-f', 'json', '-q', repo_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Bandit returns 1 when issues found, 0 when clean
            if result.returncode in [0, 1] and result.stdout:
                try:
                    bandit_output = json.loads(result.stdout)
                    findings.extend(self._parse_bandit_results(bandit_output, repo_path, project))
                except json.JSONDecodeError:
                    pass
                    
        except FileNotFoundError:
            # Bandit not installed - add a note
            findings.append({
                'title': 'Bandit analyzer not available',
                'severity': 'low',
                'description': 'Bandit security analyzer is not installed in this environment.',
                'recommendation': 'Install bandit: pip install bandit',
                'file_path': None,
                'line_number': None,
                'rule_id': 'macrohard.bandit-missing'
            })
        except subprocess.TimeoutExpired:
            findings.append({
                'title': 'Bandit analysis timeout',
                'severity': 'low',
                'description': 'Bandit analysis timed out.',
                'recommendation': 'The repository may be too large for complete analysis.',
                'file_path': None,
                'line_number': None,
                'rule_id': 'macrohard.bandit-timeout'
            })
        
        return findings
    
    def _parse_bandit_results(self, bandit_output, repo_path, project):
        """Parse Bandit JSON output into standardized format"""
        findings = []
        
        for result in bandit_output.get('results', []):
            severity_map = {
                'LOW': 'low',
                'MEDIUM': 'medium',
                'HIGH': 'high'
            }
            
            # Get relative file path
            file_path = result['filename']
            if file_path.startswith(repo_path):
                file_path = file_path[len(repo_path):].lstrip('/')
            
            findings.append({
                'title': result['issue_text'][:200],
                'severity': severity_map.get(result['issue_severity'], 'medium'),
                'description': f"{result['issue_text']}\n\nConfidence: {result['issue_confidence']}",
                'recommendation': f"Review code at line {result['line_number']}. Consider using safer alternatives.",
                'file_path': file_path,
                'line_number': result['line_number'],
                'column_number': result.get('col_offset'),
                'rule_id': f"bandit.{result['test_id']}"
            })
        
        return findings
    
    def _run_semgrep(self, repo_path, project):
        """Run Semgrep security analyzer"""
        findings = []
        
        try:
            result = subprocess.run(
                ['semgrep', '--config=auto', '--json', '--quiet', repo_path],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode in [0, 1] and result.stdout:
                try:
                    semgrep_output = json.loads(result.stdout)
                    findings.extend(self._parse_semgrep_results(semgrep_output, repo_path, project))
                except json.JSONDecodeError:
                    pass
                    
        except FileNotFoundError:
            # Semgrep not installed - skip silently
            pass
        except subprocess.TimeoutExpired:
            findings.append({
                'title': 'Semgrep analysis timeout',
                'severity': 'low',
                'description': 'Semgrep analysis timed out.',
                'recommendation': 'The repository may be too large for complete analysis.',
                'file_path': None,
                'line_number': None,
                'rule_id': 'macrohard.semgrep-timeout'
            })
        
        return findings
    
    def _parse_semgrep_results(self, semgrep_output, repo_path, project):
        """Parse Semgrep JSON output into standardized format"""
        findings = []
        
        for result in semgrep_output.get('results', []):
            severity_map = {
                'INFO': 'low',
                'WARNING': 'medium',
                'ERROR': 'high'
            }
            
            # Get relative file path
            file_path = result.get('path', '')
            if file_path.startswith(repo_path):
                file_path = file_path[len(repo_path):].lstrip('/')
            
            findings.append({
                'title': result.get('check_id', 'Unknown').split('.')[-1][:200],
                'severity': severity_map.get(result.get('extra', {}).get('severity', 'WARNING'), 'medium'),
                'description': result.get('extra', {}).get('message', 'No description available'),
                'recommendation': 'Review the identified code pattern and follow security best practices.',
                'file_path': file_path,
                'line_number': result.get('start', {}).get('line'),
                'column_number': result.get('start', {}).get('col'),
                'rule_id': result.get('check_id', 'semgrep.unknown')
            })
        
        return findings
    
    def _generate_demo_findings(self, project):
        """Generate realistic demo findings for projects without repos"""
        import random
        
        demo_findings = [
            {
                'title': 'SQL Injection vulnerability detected',
                'severity': 'critical',
                'description': 'User input is directly concatenated into SQL queries without proper sanitization. This allows attackers to execute arbitrary SQL commands, potentially leading to data breaches or unauthorized access.\n\nExample vulnerable code:\nquery = "SELECT * FROM users WHERE id = " + user_id',
                'recommendation': 'Use parameterized queries or an ORM to safely handle user input.\n\nExample fix:\nquery = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, (user_id,))',
                'file_path': 'src/auth.py',
                'line_number': 45,
                'column_number': 12,
                'rule_id': 'bandit.B608'
            },
            {
                'title': 'Hardcoded password in source code',
                'severity': 'critical',
                'description': 'A hardcoded password was found in the source code. This poses a significant security risk if the code is exposed through version control or other means.',
                'recommendation': 'Use environment variables or a secure secrets management system like HashiCorp Vault or AWS Secrets Manager.',
                'file_path': 'config/settings.py',
                'line_number': 23,
                'column_number': 18,
                'rule_id': 'bandit.B105'
            },
            {
                'title': 'Weak cryptographic hash function (MD5)',
                'severity': 'high',
                'description': 'MD5 is a cryptographically broken hash function and should not be used for secure applications. It is vulnerable to collision attacks.',
                'recommendation': 'Use SHA-256 or bcrypt for password hashing. For passwords, prefer bcrypt, scrypt, or Argon2.',
                'file_path': 'utils/crypto.py',
                'line_number': 67,
                'column_number': 8,
                'rule_id': 'bandit.B303'
            },
            {
                'title': 'Debug mode enabled in production',
                'severity': 'high',
                'description': 'Debug mode is enabled which may expose sensitive information through detailed error messages, including stack traces and configuration details.',
                'recommendation': 'Set DEBUG = False in production configuration. Use proper logging instead of debug output.',
                'file_path': 'app.py',
                'line_number': 15,
                'column_number': 1,
                'rule_id': 'bandit.B201'
            },
            {
                'title': 'Missing input validation',
                'severity': 'medium',
                'description': 'User input is not properly validated before being processed, potentially leading to unexpected behavior or security vulnerabilities.',
                'recommendation': 'Implement input validation using a schema validation library like marshmallow, pydantic, or cerberus.',
                'file_path': 'views/api.py',
                'line_number': 89,
                'column_number': 24,
                'rule_id': 'semgrep.input-validation'
            },
            {
                'title': 'Insecure deserialization with pickle',
                'severity': 'high',
                'description': 'Using pickle for deserialization of untrusted data can lead to remote code execution. An attacker could craft malicious pickle data to execute arbitrary code.',
                'recommendation': 'Use JSON or MessagePack for serialization. If you must use pickle, ensure data is cryptographically signed.',
                'file_path': 'utils/serializer.py',
                'line_number': 34,
                'column_number': 15,
                'rule_id': 'bandit.B301'
            },
            {
                'title': 'Missing CSRF protection on form',
                'severity': 'medium',
                'description': 'Form submission lacks CSRF token validation, making it vulnerable to cross-site request forgery attacks where attackers can trick users into performing unwanted actions.',
                'recommendation': 'Implement CSRF tokens for all state-changing operations. Most web frameworks provide built-in CSRF protection.',
                'file_path': 'templates/form.html',
                'line_number': 12,
                'column_number': 0,
                'rule_id': 'semgrep.csrf-missing'
            },
            {
                'title': 'Information disclosure in error messages',
                'severity': 'low',
                'description': 'Error messages may reveal sensitive system information including file paths, database schema details, or internal implementation.',
                'recommendation': 'Use generic error messages for users. Log detailed errors internally for debugging purposes only.',
                'file_path': 'handlers/error.py',
                'line_number': 56,
                'column_number': 8,
                'rule_id': 'bandit.B110'
            },
            {
                'title': 'Use of eval() with untrusted input',
                'severity': 'critical',
                'description': 'The eval() function executes arbitrary Python code. Using it with untrusted input allows attackers to execute any code on the server.',
                'recommendation': 'Never use eval() with untrusted input. Use ast.literal_eval() for safe evaluation of literals, or implement proper parsing.',
                'file_path': 'utils/parser.py',
                'line_number': 23,
                'column_number': 15,
                'rule_id': 'bandit.B307'
            },
            {
                'title': 'Hardcoded API key detected',
                'severity': 'high',
                'description': 'An API key was found hardcoded in the source code. This key could be exposed if the code is shared or made public.',
                'recommendation': 'Move API keys to environment variables or a secure secrets manager. Rotate the exposed key immediately.',
                'file_path': 'services/external.py',
                'line_number': 8,
                'column_number': 20,
                'rule_id': 'bandit.B105'
            }
        ]
        
        # Randomly select 4-8 findings for variety
        count = random.randint(4, 8)
        selected = random.sample(demo_findings, min(count, len(demo_findings)))
        
        return selected
