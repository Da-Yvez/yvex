from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from models import User  # Ensure this import matches your project structure
from wtforms import BooleanField

# Registration Form (Not modified, but included for completeness)
class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=50)])
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    
    security_question = SelectField('Security Question', choices=[
        ('first_car', "What was your first car?"),
        ('childhood_friend', "What is the name of your childhood best friend?"),
        ('favorite_teacher', "What is the name of your favorite teacher?"),
        ('birth_city', "In which city were you born?"),
        ('favorite_book', "What is your favorite book from childhood?")
    ], validators=[DataRequired()])
    security_answer = StringField('Security Question Answer', validators=[DataRequired(), Length(min=1)])
    
    # New Fields for Admin Role
    is_admin_checkbox = BooleanField('Register as Admin')
    admin_password = PasswordField('Admin Password')  # Only required if checkbox is checked

    submit = SubmitField('Register')

    def validate_password(self, field):
        """Custom password strength validation"""
        password = field.data
        if len(password) < 8:
            raise ValidationError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in password):
            raise ValidationError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in password):
            raise ValidationError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in password):
            raise ValidationError('Password must contain at least one number')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            raise ValidationError('Password must contain at least one special character')

    def validate_admin_password(self, field):
        # Validate only if the user ticks the admin checkbox
        if self.is_admin_checkbox.data:
            from flask import current_app
            ADMIN_PASSWORD = current_app.config['ADMIN_PASSWORD']
            if field.data != ADMIN_PASSWORD:
                raise ValidationError('Invalid admin password.')

# Login Form (Also includes the fields for the login)
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Form for resetting the password
class ResetPasswordForm(FlaskForm):
    # Stage 1: Username field
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    
    # Stage 2: Answer to Security Question
    security_answer = StringField('Security Question Answer', validators=[DataRequired(), Length(min=1)])
    
    # Stage 3: New Password Fields
    new_password = PasswordField('New Password', validators=[DataRequired(),])
    confirm_new_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])
    
    # Submit button for all stages
    submit = SubmitField('Submit')

    # Hidden field to handle security question info
    security_question = StringField('Security Question', validators=[DataRequired()])

    # Validate username exists in the DB
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if not user:
            raise ValidationError('No account with this username found.')

    # Validate security answer matches the stored one
    def validate_security_answer(self, security_answer):
        user = User.query.filter_by(username=self.username.data).first()
        if user:
            # Check if the provided answer matches the saved one
            if user.security_answer != security_answer.data:
                raise ValidationError('Security question answer is incorrect.')

