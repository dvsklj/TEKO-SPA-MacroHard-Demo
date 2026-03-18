"""WTForms with validation and CSRF protection"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, URL, Optional
from app.models import User


class LoginForm(FlaskForm):
    """Secure login form"""
    email = StringField('Email or username', validators=[
        DataRequired(message='Email or username is required')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required')
    ])
    remember_me = BooleanField('Remember me')
    submit = SubmitField('Sign in')


class RegistrationForm(FlaskForm):
    """Secure registration form"""
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=80, message='Username must be between 3 and 80 characters'),
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Please enter a valid email address')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=12, message='Password must be at least 12 characters'),
    ])
    password_confirm = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password'),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Create account')
    
    def validate_username(self, username):
        """Check if username is already taken"""
        user = User.query.filter_by(username=username.data.lower().strip()).first()
        if user:
            raise ValidationError('This username is already taken.')
    
    def validate_email(self, email):
        """Check if email is already registered"""
        user = User.query.filter_by(email=email.data.lower().strip()).first()
        if user:
            raise ValidationError('This email is already registered.')


class ProjectForm(FlaskForm):
    """Project creation form"""
    name = StringField('Project Name', validators=[
        DataRequired(message='Project name is required'),
        Length(min=1, max=100, message='Project name must be between 1 and 100 characters')
    ])
    repo_url = StringField('Repository URL', validators=[
        Optional(),
        URL(message='Please enter a valid URL')
    ])
    submit = SubmitField('Create Project')


class VulnerabilityStatusForm(FlaskForm):
    """Form for updating vulnerability status"""
    status = StringField('Status', validators=[DataRequired()])
    notes = TextAreaField('Notes', validators=[Optional(), Length(max=1000)])
    submit = SubmitField('Update')
