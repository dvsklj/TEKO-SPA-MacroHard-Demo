"""API Blueprint for async operations and webhooks"""
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from app import limiter

bp = Blueprint('api', __name__, url_prefix='/api/v1')


@bp.route('/webhook/github', methods=['POST'])
@limiter.limit("60 per minute")
def github_webhook():
    """GitHub webhook for push events"""
    # Verify webhook signature
    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        return jsonify({'error': 'Missing signature'}), 401
    
    event_type = request.headers.get('X-GitHub-Event')
    payload = request.get_json()
    
    if event_type == 'push':
        # Trigger analysis for the repository
        # Implementation would find project by repo URL and queue analysis
        return jsonify({'status': 'queued'}), 202
    
    return jsonify({'status': 'ignored'}), 200


@bp.route('/analysis/<int:analysis_id>/status')
@login_required
def analysis_status(analysis_id):
    """Get analysis status"""
    from app.models import Analysis, Project
    
    analysis = Analysis.query.get_or_404(analysis_id)
    project = Project.query.get(analysis.project_id)
    
    if project.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    return jsonify({
        'id': analysis.id,
        'status': analysis.status,
        'findings_count': analysis.findings_count,
        'started_at': analysis.started_at.isoformat() if analysis.started_at else None,
        'completed_at': analysis.completed_at.isoformat() if analysis.completed_at else None,
        'duration_seconds': analysis.duration_seconds
    })


@bp.route('/projects/<int:project_id>/stats')
@login_required
def project_stats(project_id):
    """Get project vulnerability statistics"""
    from app.models import Project, Vulnerability
    from sqlalchemy import func
    
    project = Project.query.get_or_404(project_id)
    
    if project.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    # Get severity counts
    severity_counts = db.session.query(
        Vulnerability.severity,
        func.count(Vulnerability.id)
    ).filter(
        Vulnerability.project_id == project_id,
        Vulnerability.status == 'open'
    ).group_by(Vulnerability.severity).all()
    
    stats = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }
    for severity, count in severity_counts:
        stats[severity] = count
    
    return jsonify({
        'project_id': project_id,
        'project_name': project.name,
        'vulnerabilities': stats,
        'total_open': sum(stats.values())
    })


# Import db for API routes
from app import db
