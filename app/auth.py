"""Authentication Blueprint with Security Features"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, current_user, login_required
from app.models import User, AuditLog
from app.forms import LoginForm, RegistrationForm
from app import db, limiter

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    """Secure login endpoint with rate limiting"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.email.data.strip()
        normalized = identifier.lower()

        user = User.query.filter_by(email=normalized).first()
        if not user:
            user = User.query.filter_by(username=identifier).first()

        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('Your account has been disabled. Please contact support.', 'error')
                _log_audit(None, 'login_failed_disabled', ip_address=request.remote_addr)
                return render_template('auth/login.html', form=form)
            
            # Successful login
            login_user(user, remember=form.remember_me.data)
            user.update_last_login()
            
            # Log successful login
            _log_audit(user.id, 'login_success', ip_address=request.remote_addr,
                      user_agent=request.user_agent.string)
            
            flash('Welcome back!', 'success')
            
            # Redirect to requested page or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('main.dashboard'))
        else:
            # Failed login
            _log_audit(user.id if user else None, 'login_failed', 
                      ip_address=request.remote_addr,
                      details=f'Identifier: {identifier}')
            flash('Invalid email or password', 'error')
    
    return render_template('auth/login.html', form=form)


@bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def register():
    """Secure registration endpoint with rate limiting"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            email=form.email.data.lower().strip(),
            username=form.username.data.strip()
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        # Log registration
        _log_audit(user.id, 'register', ip_address=request.remote_addr,
                  user_agent=request.user_agent.string)
        
        flash('Account created successfully! Please sign in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html', form=form)


@bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Secure logout endpoint"""
    _log_audit(current_user.id, 'logout', ip_address=request.remote_addr)
    logout_user()
    flash('You have been signed out.', 'info')
    return redirect(url_for('auth.login'))


def _log_audit(user_id, action, resource_type=None, resource_id=None, 
               ip_address=None, user_agent=None, details=None):
    """Helper to create audit log entries"""
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details
    )
    db.session.add(log)
    db.session.commit()
