# ============ IMPORTS ============
import os
import jwt
from datetime import timedelta
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============ INITIALIZATION ============
app = Flask(__name__)
CORS(app, origins=[os.getenv('CORS_ORIGIN', '*')])

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

db = SQLAlchemy(app)

# Password Hashing with Argon2
ph = PasswordHasher()

# Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# ============ DATABASE MODELS ============

class Tenant(db.Model):
    __tablename__ = 'tenants'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Class(db.Model):
    __tablename__ = 'classes'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'))
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    term_registered = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(50), default='active')
    added_by = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_updated = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class Subject(db.Model):
    __tablename__ = 'subjects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'))
    subject_id = db.Column(db.Integer, db.ForeignKey('subjects.id'))
    session = db.Column(db.String(20))
    records = db.Column(db.JSON, nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    term = db.Column(db.String(20), nullable=False)
    taken_by = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class TeacherAssignment(db.Model):
    __tablename__ = 'teacher_assignments'
    id = db.Column(db.Integer, primary_key=True)
    teacher_email = db.Column(db.String(255), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'))
    subject_id = db.Column(db.Integer, db.ForeignKey('subjects.id'))
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    assigned_by = db.Column(db.String(255))
    assigned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# ============ HELPER FUNCTIONS ============

def hash_password(password):
    """Hash password using Argon2 with salt"""
    return ph.hash(password)

def verify_password(password, password_hash):
    """Verify password against Argon2 hash"""
    try:
        ph.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False

def generate_token(user_id, tenant_id, role):
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'tenant_id': tenant_id,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(hours=int(os.getenv('JWT_EXPIRES_HOURS', 8)))
    }
    return jwt.encode(payload, os.getenv('JWT_SECRET'), algorithm='HS256')

def token_required(f):
    """Decorator to verify JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token missing'}), 401

        try:
            data = jwt.decode(token, os.getenv('JWT_SECRET'), algorithms=['HS256'])
            g.user_id = data['user_id']
            g.tenant_id = data['tenant_id']
            g.role = data['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

        return f(*args, **kwargs)
    return decorated

def admin_only(f):
    """Decorator to allow only admins"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.role not in ['super_admin', 'admin']:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

# Get super admin emails from env
SUPER_ADMIN_EMAILS = os.getenv('SUPER_ADMIN_EMAILS', 'admin1@school.com,admin2@school.com,admin3@school.com').split(',')

# ============ AUTHENTICATION ENDPOINTS ============

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """Login endpoint with rate limiting"""
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    if not verify_password(password, user.password_hash):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = generate_token(user.id, user.tenant_id, user.role)

    return jsonify({
        'token': token,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'role': user.role,
            'tenant_id': user.tenant_id
        }
    })

@app.route('/api/auth/verify', methods=['GET'])
@token_required
def verify_token():
    return jsonify({'valid': True, 'role': g.role})

# ============ USER MANAGEMENT ============

@app.route('/api/users/teachers', methods=['POST'])
@token_required
@admin_only
def add_teacher():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    name = data.get('name', '').strip()
    role = data.get('role', 'teacher')
    password = data.get('password', '')

    if not email or not name or not password:
        return jsonify({'error': 'Email, name, and password required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'User already exists'}), 409

    new_user = User(
        email=email,
        name=name,
        password_hash=hash_password(password),
        role=role,
        tenant_id=g.tenant_id
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Teacher added successfully'}), 201

@app.route('/api/users/teachers', methods=['GET'])
@token_required
@admin_only
def get_teachers():
    teachers = User.query.filter_by(tenant_id=g.tenant_id).filter(User.role.in_(['teacher', 'classteacher'])).all()
    return jsonify([{'id': t.id, 'name': t.name, 'email': t.email, 'role': t.role} for t in teachers])

# ============ CLASS MANAGEMENT ============

@app.route('/api/classes', methods=['POST'])
@token_required
@admin_only
def create_class():
    data = request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Class name required'}), 400
    new_class = Class(name=name, tenant_id=g.tenant_id)
    db.session.add(new_class)
    db.session.commit()
    return jsonify({'id': new_class.id, 'name': new_class.name}), 201

@app.route('/api/classes', methods=['GET'])
@token_required
def get_classes():
    classes = Class.query.filter_by(tenant_id=g.tenant_id).all()
    return jsonify([{'id': c.id, 'name': c.name} for c in classes])

# ============ SUBJECT MANAGEMENT ============

@app.route('/api/subjects', methods=['POST'])
@token_required
@admin_only
def create_subject():
    data = request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Subject name required'}), 400
    new_subject = Subject(name=name, tenant_id=g.tenant_id)
    db.session.add(new_subject)
    db.session.commit()
    return jsonify({'id': new_subject.id, 'name': new_subject.name}), 201

@app.route('/api/subjects', methods=['GET'])
@token_required
def get_subjects():
    subjects = Subject.query.filter(
        (Subject.tenant_id == g.tenant_id) | (Subject.tenant_id.is_(None))
    ).all()
    return jsonify([{'id': s.id, 'name': s.name} for s in subjects])

# ============ STUDENT MANAGEMENT ============

@app.route('/api/students', methods=['POST'])
@token_required
@admin_only
def register_student():
    data = request.get_json()
    name = data.get('name', '').strip()
    class_id = data.get('class_id')
    term = data.get('term', '')
    status = data.get('status', 'active')

    if not name or not class_id or not term:
        return jsonify({'error': 'Name, class, and term required'}), 400

    existing = Student.query.filter_by(
        name=name, class_id=class_id, tenant_id=g.tenant_id, term_registered=term
    ).first()

    if existing:
        existing.status = status
        existing.last_updated = datetime.now(timezone.utc)
        db.session.commit()
        return jsonify({'message': 'Student updated', 'id': existing.id})

    new_student = Student(
        name=name, class_id=class_id, tenant_id=g.tenant_id,
        term_registered=term, status=status, added_by=str(g.user_id)
    )
    db.session.add(new_student)
    db.session.commit()
    return jsonify({'message': 'Student registered', 'id': new_student.id}), 201

@app.route('/api/students', methods=['GET'])
@token_required
def get_students():
    term = request.args.get('term', '')
    class_id = request.args.get('class_id')
    query = Student.query.filter_by(tenant_id=g.tenant_id)
    if term:
        query = query.filter_by(term_registered=term)
    if class_id:
        query = query.filter_by(class_id=class_id)
    students = query.all()
    return jsonify([{'id': s.id, 'name': s.name, 'class_id': s.class_id, 'status': s.status, 'term_registered': s.term_registered} for s in students])

# ============ ATTENDANCE MANAGEMENT ============

@app.route('/api/attendance', methods=['POST'])
@token_required
@admin_only
def save_attendance():
    data = request.get_json()
    date = data.get('date')
    class_id = data.get('class_id')
    subject_id = data.get('subject_id')
    session = data.get('session')
    records = data.get('records')
    term = data.get('term')

    if not all([date, class_id, subject_id, session, records, term]):
        return jsonify({'error': 'Missing required fields'}), 400

    existing = Attendance.query.filter_by(
        date=date, class_id=class_id, subject_id=subject_id,
        session=session, tenant_id=g.tenant_id, term=term
    ).first()

    if existing:
        existing.records = records
        existing.taken_by = str(g.user_id)
    else:
        new_attendance = Attendance(
            date=date, class_id=class_id, subject_id=subject_id,
            session=session, records=records, tenant_id=g.tenant_id,
            term=term, taken_by=str(g.user_id)
        )
        db.session.add(new_attendance)

    db.session.commit()
    return jsonify({'message': 'Attendance saved'})

@app.route('/api/attendance', methods=['GET'])
@token_required
def get_attendance():
    term = request.args.get('term')
    class_id = request.args.get('class_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = Attendance.query.filter_by(tenant_id=g.tenant_id)
    if term:
        query = query.filter_by(term=term)
    if class_id:
        query = query.filter_by(class_id=class_id)
    if start_date:
        query = query.filter(Attendance.date >= start_date)
    if end_date:
        query = query.filter(Attendance.date <= end_date)

    attendance = query.order_by(Attendance.date.desc()).limit(100).all()
    return jsonify([{
        'id': a.id, 'date': a.date.isoformat(), 'class_id': a.class_id,
        'subject_id': a.subject_id, 'session': a.session, 'records': a.records,
        'term': a.term, 'taken_by': a.taken_by
    } for a in attendance])

# ============ REPORTS ============

@app.route('/api/reports/attendance-summary', methods=['GET'])
@token_required
def attendance_summary():
    term = request.args.get('term')
    class_id = request.args.get('class_id')

    query = Attendance.query.filter_by(tenant_id=g.tenant_id, term=term)
    if class_id:
        query = query.filter_by(class_id=class_id)

    attendance_records = query.all()

    stats = {}
    for record in attendance_records:
        for student_id, status in record.records.items():
            sid = str(student_id)
            if sid not in stats:
                stats[sid] = {'present': 0, 'absent': 0, 'sick': 0, 'emergency': 0, 'total': 0}
            stats[sid][status] = stats[sid].get(status, 0) + 1
            stats[sid]['total'] += 1

    student_ids = [int(sid) for sid in stats.keys()]
    students = Student.query.filter(Student.id.in_(student_ids)).all()
    student_map = {s.id: s.name for s in students}

    result = []
    for student_id, s in stats.items():
        rate = (s['present'] / s['total'] * 100) if s['total'] > 0 else 0
        result.append({
            'student_id': int(student_id),
            'student_name': student_map.get(int(student_id), 'Unknown'),
            'present': s['present'], 'absent': s['absent'],
            'sick': s['sick'], 'emergency': s['emergency'],
            'total': s['total'], 'attendance_rate': round(rate, 1)
        })

    return jsonify(result)

# ============ INITIALIZE DATABASE ============

def init_db():
    db.create_all()

    tenant = Tenant.query.filter_by(name='Raven School').first()
    if not tenant:
        tenant = Tenant(name='Raven School')
        db.session.add(tenant)
        db.session.commit()

    for email in SUPER_ADMIN_EMAILS:
        if email and not User.query.filter_by(email=email).first():
            hashed = hash_password('pass123')
            super_admin = User(
                email=email, name=f'Admin {email.split("@")[0]}',
                password_hash=hashed, role='super_admin', tenant_id=tenant.id
            )
            db.session.add(super_admin)

    db.session.commit()
    print("✅ Database initialized with super admins")

# ============ RUN APP ============
if __name__ == '__main__':
    with app.app_context():
        init_db()
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)