import os
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv
from sqlalchemy import text

load_dotenv()

app = Flask(__name__)
CORS(app, origins='*')

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

db = SQLAlchemy(app)
ph = PasswordHasher()

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

class Tenant(db.Model):
    __tablename__ = 'tenants'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Class(db.Model):
    __tablename__ = 'classes'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'))
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    term_registered = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(50), default='active')
    added_by = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Subject(db.Model):
    __tablename__ = 'subjects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TeacherAssignment(db.Model):
    __tablename__ = 'teacher_assignments'
    id = db.Column(db.Integer, primary_key=True)
    teacher_email = db.Column(db.String(255), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('classes.id'))
    subject_id = db.Column(db.Integer, db.ForeignKey('subjects.id'))
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenants.id'))
    assigned_by = db.Column(db.String(255))
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)

def hash_password(password):
    return ph.hash(password)

def verify_password(password, password_hash):
    try:
        ph.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False

def generate_token(user_id, tenant_id, role):
    payload = {
        'user_id': user_id,
        'tenant_id': tenant_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=int(os.getenv('JWT_EXPIRES_HOURS', 8)))
    }
    return jwt.encode(payload, os.getenv('JWT_SECRET'), algorithm='HS256')

def token_required(f):
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
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.role not in ['super_admin', 'admin']:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

@app.errorhandler(500)
def handle_500(e):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(404)
def handle_404(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400

        user = User.query.filter_by(email=email).first()
        if not user or not verify_password(password, user.password_hash):
            return jsonify({'error': 'Invalid credentials'}), 401

        token = generate_token(user.id, user.tenant_id, user.role)
        tenant = Tenant.query.get(user.tenant_id)

        return jsonify({
            'token': token,
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'tenant_id': user.tenant_id
            },
            'tenant': {
                'id': tenant.id if tenant else None,
                'name': tenant.name if tenant else 'Raven School'
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/verify', methods=['GET'])
@token_required
def verify_token():
    return jsonify({'valid': True, 'role': g.role, 'tenant_id': g.tenant_id})

@app.route('/api/auth/change-password', methods=['POST'])
@token_required
def change_password():
    try:
        data = request.get_json()
        old_password = data.get('old_password')
        new_password = data.get('new_password')

        if not old_password or not new_password:
            return jsonify({'error': 'Old and new password required'}), 400

        if len(new_password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        user = User.query.get(g.user_id)
        if not verify_password(old_password, user.password_hash):
            return jsonify({'error': 'Current password is incorrect'}), 401

        user.password_hash = hash_password(new_password)
        db.session.commit()

        return jsonify({'message': 'Password changed successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/teachers', methods=['POST'])
@token_required
@admin_only
def add_teacher():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        name = data.get('name', '').strip()
        role = data.get('role', 'teacher')
        password = data.get('password', '')

        if not email or not name or not password:
            return jsonify({'error': 'Email, name, and password required'}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'User already exists'}), 409

        user = User(
            email=email, name=name,
            password_hash=hash_password(password),
            role=role, tenant_id=g.tenant_id
        )
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'Teacher added', 'id': user.id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/teachers', methods=['GET'])
@token_required
@admin_only
def get_teachers():
    try:
        teachers = User.query.filter_by(tenant_id=g.tenant_id).filter(User.role.in_(['teacher', 'classteacher'])).all()
        return jsonify([{'id': t.id, 'name': t.name, 'email': t.email, 'role': t.role} for t in teachers])
    except Exception as e:
        return jsonify([])

@app.route('/api/classes', methods=['POST'])
@token_required
@admin_only
def create_class():
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'error': 'Class name required'}), 400

        new_class = Class(name=name, tenant_id=g.tenant_id)
        db.session.add(new_class)
        db.session.commit()
        return jsonify({'id': new_class.id, 'name': new_class.name}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/classes', methods=['GET'])
@token_required
def get_classes():
    try:
        classes = Class.query.filter_by(tenant_id=g.tenant_id).all()
        return jsonify([{'id': c.id, 'name': c.name} for c in classes])
    except Exception as e:
        return jsonify([])

@app.route('/api/subjects', methods=['POST'])
@token_required
@admin_only
def create_subject():
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'error': 'Subject name required'}), 400

        subject = Subject(name=name, tenant_id=g.tenant_id)
        db.session.add(subject)
        db.session.commit()
        return jsonify({'id': subject.id, 'name': subject.name}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/subjects', methods=['GET'])
@token_required
def get_subjects():
    try:
        subjects = Subject.query.filter(
            (Subject.tenant_id == g.tenant_id) | (Subject.tenant_id.is_(None))
        ).all()
        return jsonify([{'id': s.id, 'name': s.name} for s in subjects])
    except Exception as e:
        return jsonify([])

@app.route('/api/students', methods=['POST'])
@token_required
def register_student():
    try:
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
            existing.last_updated = datetime.utcnow()
            db.session.commit()
            return jsonify({'message': 'Student updated', 'id': existing.id})

        student = Student(
            name=name, class_id=class_id, tenant_id=g.tenant_id,
            term_registered=term, status=status, added_by=str(g.user_id)
        )
        db.session.add(student)
        db.session.commit()
        return jsonify({'message': 'Student registered', 'id': student.id}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/students', methods=['GET'])
@token_required
def get_students():
    try:
        term = request.args.get('term', '')
        class_id = request.args.get('class_id')
        query = Student.query.filter_by(tenant_id=g.tenant_id)
        if term:
            query = query.filter_by(term_registered=term)
        if class_id:
            query = query.filter_by(class_id=class_id)

        students = query.all()
        return jsonify([{
            'id': s.id,
            'name': s.name,
            'classId': s.class_id,
            'termRegistered': s.term_registered,
            'status': s.status
        } for s in students])
    except Exception as e:
        return jsonify([])

@app.route('/api/students/<int:student_id>', methods=['PUT'])
@token_required
@admin_only
def update_student(student_id):
    try:
        data = request.get_json()
        student = Student.query.filter_by(id=student_id, tenant_id=g.tenant_id).first()
        if not student:
            return jsonify({'error': 'Student not found'}), 404

        if 'status' in data:
            student.status = data['status']
        if 'name' in data:
            student.name = data['name'].strip()
        if 'class_id' in data:
            student.class_id = data['class_id']

        student.last_updated = datetime.utcnow()
        db.session.commit()
        return jsonify({'message': 'Student updated'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/students/cleanup', methods=['POST'])
@token_required
@admin_only
def cleanup_students():
    try:
        term = request.get_json().get('term', '')
        if not term:
            return jsonify({'error': 'Term required'}), 400

        result = Student.query.filter_by(tenant_id=g.tenant_id).filter(
            Student.term_registered != term
        ).delete(synchronize_session=False)

        db.session.commit()
        return jsonify({'message': f'Removed {result} inactive students'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/teacher-assignments', methods=['POST'])
@token_required
@admin_only
def assign_subject():
    try:
        data = request.get_json()
        teacher_email = data.get('teacher_email', '').strip().lower()
        class_id = data.get('class_id')
        subject_id = data.get('subject_id')

        if not teacher_email or not class_id or not subject_id:
            return jsonify({'error': 'All fields required'}), 400

        assignment = TeacherAssignment(
            teacher_email=teacher_email,
            class_id=class_id,
            subject_id=subject_id,
            tenant_id=g.tenant_id,
            assigned_by=str(g.user_id)
        )
        db.session.add(assignment)
        db.session.commit()
        return jsonify({'message': 'Subject assigned'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/teacher-assignments', methods=['GET'])
@token_required
def get_assignments():
    try:
        assignments = TeacherAssignment.query.filter_by(tenant_id=g.tenant_id).all()
        return jsonify([{
            'id': a.id,
            'teacherEmail': a.teacher_email,
            'classId': a.class_id,
            'subjectId': a.subject_id
        } for a in assignments])
    except Exception as e:
        return jsonify([])

@app.route('/api/users/teachers/<int:user_id>', methods=['DELETE'])
@token_required
@admin_only
def delete_teacher(user_id):
    user = User.query.filter_by(id=user_id, tenant_id=g.tenant_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'Teacher deleted'})

@app.route('/api/classes/<int:class_id>', methods=['DELETE'])
@token_required
@admin_only
def delete_class(class_id):
    cls = Class.query.filter_by(id=class_id, tenant_id=g.tenant_id).first()
    if not cls:
        return jsonify({'error': 'Class not found'}), 404
    db.session.delete(cls)
    db.session.commit()
    return jsonify({'message': 'Class deleted'})

@app.route('/api/subjects/<int:subject_id>', methods=['DELETE'])
@token_required
@admin_only
def delete_subject(subject_id):
    subj = Subject.query.filter_by(id=subject_id, tenant_id=g.tenant_id).first()
    if not subj:
        return jsonify({'error': 'Subject not found'}), 404
    db.session.delete(subj)
    db.session.commit()
    return jsonify({'message': 'Subject deleted'})

@app.route('/api/attendance', methods=['POST'])
@token_required
def save_attendance():
    try:
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
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attendance', methods=['GET'])
@token_required
def get_attendance():
    try:
        term = request.args.get('term')
        class_id = request.args.get('class_id')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        limit = request.args.get('limit', 100, type=int)

        query = Attendance.query.filter_by(tenant_id=g.tenant_id)
        if term:
            query = query.filter_by(term=term)
        if class_id:
            query = query.filter_by(class_id=class_id)
        if start_date:
            query = query.filter(Attendance.date >= start_date)
        if end_date:
            query = query.filter(Attendance.date <= end_date)

        records = query.order_by(Attendance.date.desc()).limit(limit).all()
        return jsonify([{
            'id': a.id,
            'date': a.date.isoformat(),
            'classId': a.class_id,
            'subjectId': a.subject_id,
            'session': a.session,
            'records': a.records,
            'term': a.term,
            'takenBy': a.taken_by
        } for a in records])
    except Exception as e:
        return jsonify([])

@app.route('/api/reports/attendance-summary', methods=['GET'])
@token_required
def attendance_summary():
    try:
        term = request.args.get('term')
        class_id = request.args.get('class_id')

        query = Attendance.query.filter_by(tenant_id=g.tenant_id, term=term)
        if class_id:
            query = query.filter_by(class_id=class_id)

        attendance_records = query.all()
        stats = {}

        for record in attendance_records:
            if isinstance(record.records, list):
                for rec in record.records:
                    sid = str(rec.get('studentId'))
                    status = rec.get('status')
                    if sid and status:
                        if sid not in stats:
                            stats[sid] = {'present': 0, 'absent': 0, 'sick': 0, 'emergency': 0, 'total': 0}
                        stats[sid][status] = stats[sid].get(status, 0) + 1
                        stats[sid]['total'] += 1
            elif isinstance(record.records, dict):
                for sid, status in record.records.items():
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
                'studentId': int(student_id),
                'studentName': student_map.get(int(student_id), 'Unknown'),
                'present': s['present'],
                'absent': s['absent'],
                'sick': s['sick'],
                'emergency': s['emergency'],
                'total': s['total'],
                'attendanceRate': round(rate, 1)
            })

        return jsonify(result)
    except Exception as e:
        return jsonify([])

@app.route('/api/school/data', methods=['GET'])
@token_required
def school_data():
    try:
        term = request.args.get('term', '')
        teachers = User.query.filter_by(tenant_id=g.tenant_id).filter(User.role.in_(['teacher', 'classteacher'])).all()
        students = Student.query.filter_by(tenant_id=g.tenant_id, term_registered=term).all()
        classes = Class.query.filter_by(tenant_id=g.tenant_id).all()
        subjects = Subject.query.filter((Subject.tenant_id == g.tenant_id) | (Subject.tenant_id.is_(None))).all()

        return jsonify({
            'teachers': [{'id': t.id, 'name': t.name, 'email': t.email.split('@')[0] + '@...', 'role': t.role} for t in teachers],
            'students': [{'id': s.id, 'name': s.name, 'status': s.status} for s in students],
            'classes': [{'id': c.id, 'name': c.name} for c in classes],
            'subjects': [{'id': s.id, 'name': s.name} for s in subjects]
        })
    except Exception as e:
        return jsonify({'teachers': [], 'students': [], 'classes': [], 'subjects': []})

@app.route('/')
def home():
    return jsonify({'message': 'Raven Attendance API is running', 'status': 'online'})

with app.app_context():
    try:
        db.create_all()
        print(" Database tables created")

        columns_to_add = [
            "class_id INTEGER",
            "tenant_id INTEGER",
            "term_registered VARCHAR(20)",
            "status VARCHAR(50) DEFAULT 'active'",
            "added_by VARCHAR(255)",
            "last_updated TIMESTAMP"
        ]

        with db.engine.connect() as conn:
            for column in columns_to_add:
                try:
                    conn.execute(text(f"ALTER TABLE students ADD COLUMN IF NOT EXISTS {column}"))
                    conn.commit()
                except:
                    pass

            try:
                conn.execute(text("ALTER TABLE students RENAME COLUMN class TO class_id"))
                conn.commit()
            except:
                pass

        tenants_data = [
            {"name": "Raven School", "admin_email": "admin1@school.com", "admin_name": "Raven School"},
            {"name": "Eagle School", "admin_email": "admin2@school.com", "admin_name": "Eagle School"},
            {"name": "Hawk School", "admin_email": "admin3@school.com", "admin_name": "Hawk School"}
        ]

        for t_data in tenants_data:
            tenant = Tenant.query.filter_by(name=t_data["name"]).first()
            if not tenant:
                tenant = Tenant(name=t_data["name"])
                db.session.add(tenant)
                db.session.commit()
                print(f" Created tenant: {t_data['name']}")

            email = t_data["admin_email"]
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(
                    email=email,
                    name=t_data["admin_name"],
                    password_hash=hash_password('pass123'),
                    role='super_admin',
                    tenant_id=tenant.id
                )
                db.session.add(user)
                print(f" Created admin: {email} | Password: pass123 | Tenant: {t_data['name']}")
            else:
                user.tenant_id = tenant.id
                user.name = t_data["admin_name"]
                print(f" Updated admin: {email} | Tenant: {t_data['name']}")

        db.session.commit()
        print(" Multi-tenant database initialized")
        print(" Default Password for all admins: pass123")
        print("Autorized en designed br RAVEN")

    except Exception as e:
        print(f" Init error: {e}")

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
