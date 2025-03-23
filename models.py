from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, time, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):  # User model
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    security_question = db.Column(db.String(250), nullable=False)
    security_answer = db.Column(db.String(250), nullable=False)  # To store the answer
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<User {self.username}>"

    def set_password(self, password):
        """Hashes the password before saving"""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Checks the provided password against the stored hash"""
        return check_password_hash(self.password, password)
    
class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    department_name = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)  # Hashed password for department protection

    def __repr__(self):
        return f"<Department {self.department_name}>"

    def set_password(self, password):
        """Hashes the department password before saving"""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Checks the provided password against the stored hash"""
        return check_password_hash(self.password, password)
    
# New FileMetadata model
class FileMetadata(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)  # New field for original filename
    size = db.Column(db.Integer, nullable=False)
    last_modified = db.Column(db.DateTime, default=db.func.current_timestamp())
    department = db.Column(db.String(100), nullable=False)
    owner = db.Column(db.String(150), nullable=False)
    encryption_metadata = db.Column(db.Text)  # New field for ZKE metadata
    is_public = db.Column(db.Boolean, default=False) 

class DepartmentAuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=False)
    user = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


    def __repr__(self):
        return f'<File {self.original_filename} uploaded by {self.owner} in {self.department}>'

