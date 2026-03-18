"""Main Application Blueprint"""
import csv
import io
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, Response, jsonify
from flask_login import login_required, current_user
from app.models import Project, Vulnerability, Analysis, AuditLog
from app.forms import ProjectForm, VulnerabilityStatusForm
from app.analyzer import SecurityAnalyzer
from app import db, limiter

bp = Blueprint('main', __name__)


@bp.route('/')
def index():
    """Landing page"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('index.html')


@bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with security overview"""
    projects = current_user.projects.filter_by(is_active=True).all()
    
    # Aggregate stats across all projects
    total_critical = sum(p.critical_count for p in projects)
    total_high = sum(p.high_count for p in projects)
    total_medium = sum(p.medium_count for p in projects)
    total_low = sum(p.low_count for p in projects)
    
    # Recent vulnerabilities
    recent_vulns = Vulnerability.query.join(Project).filter(
        Project.user_id == current_user.id,
        Vulnerability.status == 'open'
    ).order_by(Vulnerability.created_at.desc()).limit(10).all()
    
    # Recent analyses
    recent_analyses = Analysis.query.join(Project).filter(
        Project.user_id == current_user.id
    ).order_by(Analysis.started_at.desc()).limit(5).all()
    
    return render_template('dashboard.html',
                         projects=projects,
                         total_critical=total_critical,
                         total_high=total_high,
                         total_medium=total_medium,
                         total_low=total_low,
                         recent_vulns=recent_vulns,
                         recent_analyses=recent_analyses)


@bp.route('/projects/new', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def new_project():
    """Create new project"""
    form = ProjectForm()
    if form.validate_on_submit():
        project = Project(
            name=form.name.data.strip(),
            repo_url=form.repo_url.data.strip() if form.repo_url.data else None,
            user_id=current_user.id
        )
        db.session.add(project)
        db.session.commit()
        
        _log_audit('create_project', project.id)
        flash(f'Project "{project.name}" created successfully', 'success')
        
        # Run initial analysis if repo URL provided
        if project.repo_url:
            return redirect(url_for('main.project_detail', project_id=project.id))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{field}: {error}', 'error')
    
    return redirect(url_for('main.dashboard'))


@bp.route('/project/<int:project_id>')
@login_required
def project_detail(project_id):
    """Project detail page with vulnerabilities"""
    project = Project.query.get_or_404(project_id)
    
    if project.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Get vulnerabilities sorted by severity
    vulnerabilities = project.vulnerabilities.filter_by(status='open').order_by(
        db.case(
            (Vulnerability.severity == 'critical', 1),
            (Vulnerability.severity == 'high', 2),
            (Vulnerability.severity == 'medium', 3),
            (Vulnerability.severity == 'low', 4),
        ),
        Vulnerability.created_at.desc()
    ).all()
    
    analyses = project.analyses.order_by(Analysis.started_at.desc()).limit(10).all()
    
    return render_template('project_detail.html',
                         project=project,
                         vulnerabilities=vulnerabilities,
                         analyses=analyses)


@bp.route('/project/<int:project_id>/analyze', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def analyze_project(project_id):
    """Run security analysis on project"""
    project = Project.query.get_or_404(project_id)
    
    if project.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Create analysis record
    analysis = Analysis(
        project_id=project.id,
        status='running',
        triggered_by=current_user.id
    )
    db.session.add(analysis)
    db.session.commit()
    
    # Run analysis
    analyzer = SecurityAnalyzer()
    try:
        findings = analyzer.analyze_project(project, analysis)
        
        _log_audit('run_analysis', project.id, details=f'Findings: {len(findings)}')
        
        if len(findings) > 0:
            flash(f'Analysis complete. Found {len(findings)} new issues.', 'success')
        else:
            flash('Analysis complete. No new issues found.', 'success')
            
    except Exception as e:
        analysis.status = 'failed'
        analysis.error_message = str(e)
        db.session.commit()
        
        flash(f'Analysis failed: {str(e)}', 'error')
    
    return redirect(url_for('main.project_detail', project_id=project.id))


@bp.route('/project/<int:project_id>/export')
@login_required
def export_csv(project_id):
    """Export vulnerabilities to CSV"""
    project = Project.query.get_or_404(project_id)
    
    if project.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('main.dashboard'))
    
    vulns = project.vulnerabilities.all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Title', 'Severity', 'File Path', 'Line', 'Column', 
                     'Rule ID', 'Status', 'Created', 'Description'])
    
    for v in vulns:
        writer.writerow([
            v.id,
            v.title,
            v.severity,
            v.file_path,
            v.line_number,
            v.column_number,
            v.rule_id,
            v.status,
            v.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            v.description  # Decrypted automatically
        ])
    
    output.seek(0)
    
    _log_audit('export_csv', project.id)
    
    return Response(
        output,
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=macrohard_{project.name}_{datetime.now().strftime("%Y%m%d")}.csv'
        }
    )


@bp.route('/vulnerability/<int:vuln_id>/update', methods=['POST'])
@login_required
def update_vulnerability(vuln_id):
    """Update vulnerability status"""
    vuln = Vulnerability.query.get_or_404(vuln_id)
    
    if vuln.project.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('main.dashboard'))
    
    status = request.form.get('status')
    if status in ['open', 'resolved', 'false_positive', 'ignored']:
        old_status = vuln.status
        vuln.status = status
        if status == 'resolved':
            vuln.resolved_at = datetime.utcnow()
            vuln.resolved_by = current_user.id
        db.session.commit()
        
        _log_audit('update_vulnerability', vuln.project.id, 
                  details=f'Vuln {vuln_id}: {old_status} -> {status}')
        flash('Status updated', 'success')
    else:
        flash('Invalid status', 'error')
    
    return redirect(url_for('main.project_detail', project_id=vuln.project.id))


def _log_audit(action, resource_id=None, details=None):
    """Helper to create audit log"""
    log = AuditLog(
        user_id=current_user.id,
        action=action,
        resource_type='project',
        resource_id=resource_id,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        details=details
    )
    db.session.add(log)
    db.session.commit()
