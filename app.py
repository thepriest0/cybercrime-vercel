from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    reports = db.relationship('Report', backref='user', lazy=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    chat_log = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    evidence_filename = db.Column(db.String(200), nullable=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(fullname=fullname, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    current_user = User.query.get(user_id)
    reports = Report.query.filter_by(user_id=user_id).order_by(Report.date.desc()).all()

    return render_template('user_dashboard.html', user=current_user, reports=reports)

@app.route('/user_settings', methods=['GET', 'POST'])
def user_settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    current_user = User.query.get(user_id)

    if request.method == 'POST':
        current_user.fullname = request.form['fullname']
        current_user.email = request.form['email']
        if request.form['password']:
            current_user.password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')

        db.session.commit()
        return redirect(url_for('user_settings'))

    return render_template('user_settings.html', user=current_user)

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    current_user = User.query.get(user_id)
    if not current_user.is_admin:
        return redirect(url_for('login'))

    total_users = User.query.count()
    total_reports = Report.query.count()
    visits = 0 # Implement a visit count logic if necessary

    return render_template('admin_dashboard.html', total_users=total_users, total_reports=total_reports, visits=visits)

@app.route('/admin_settings', methods=['GET', 'POST'])
def admin_settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    current_user = User.query.get(user_id)
    if not current_user.is_admin:
        return redirect(url_for('login'))

    if request.method == 'POST':
        admin_email = request.form['admin_email']
        admin_password = request.form['admin_password']

        current_user.email = admin_email
        if admin_password:
            current_user.password = generate_password_hash(admin_password, method='pbkdf2:sha256')

        db.session.commit()
        return redirect(url_for('admin_settings'))

    return render_template('admin_settings.html', admin_email=current_user.email)

@app.route('/admin/reports', methods=['GET'])
def admin_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    current_user = User.query.get(user_id)
    if not current_user.is_admin:
        return redirect(url_for('login'))

    search_query = request.args.get('search', '')
    sort_by = request.args.get('sort_by', 'id')
    sort_order = request.args.get('sort_order', 'asc')

    query = Report.query.join(User)

    if search_query:
        if search_query.isdigit() and sort_by == 'id':
            query = query.filter(Report.id.like(f'%{search_query}%'))
        elif sort_by == 'date':
            query = query.filter(Report.date.like(f'%{search_query}%'))
        else:
            query = query.filter(
                (User.fullname.like(f'%{search_query}%')) | 
                (User.email.like(f'%{search_query}%')) | 
                (Report.chat_log.like(f'%{search_query}%'))
            )

    if sort_by == 'id':
        query = query.order_by(Report.id.desc() if sort_order == 'desc' else Report.id.asc())
    elif sort_by == 'fullname':
        query = query.order_by(User.fullname.desc() if sort_order == 'desc' else User.fullname.asc())
    elif sort_by == 'email':
        query = query.order_by(User.email.desc() if sort_order == 'desc' else User.email.asc())
    elif sort_by == 'date':
        query = query.order_by(Report.date.desc() if sort_order == 'desc' else Report.date.asc())

    reports = query.all()
    return render_template('admin_reports.html', reports=reports, search_query=search_query, sort_by=sort_by, sort_order=sort_order)

@app.route('/admin_users')
def admin_users():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    current_user = User.query.get(user_id)
    if not current_user.is_admin:
        return redirect(url_for('login'))

    users = User.query.order_by(User.fullname).all()
    return render_template('admin_users.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('admin_users'))

@app.route('/delete_report/<int:report_id>', methods=['POST'])
def delete_report(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    if not current_user.is_admin:
        return redirect(url_for('login'))

    report = Report.query.get(report_id)
    if report:
        db.session.delete(report)
        db.session.commit()
    return redirect(url_for('admin_reports'))

@app.route('/user_view_chat_log/<int:report_id>')
def user_view_chat_log(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    report = Report.query.get(report_id)
    if not report:
        return "Report not found", 404

    user = User.query.get(report.user_id)
    if not user:
        return "User not found", 404

    current_user = User.query.get(session['user_id'])

    if report.user_id != current_user.id:
        return "Unauthorized access", 403

    chat_log_lines = report.chat_log.split('\n')
    return render_template('user_view_chat_log.html', report=report, user=user, chat_log_lines=chat_log_lines)

@app.route('/admin_view_chat_log/<int:report_id>')
def admin_view_chat_log(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    current_user = User.query.get(user_id)
    if not current_user.is_admin:
        return redirect(url_for('login'))

    report = Report.query.get(report_id)
    if not report:
        return "Report not found", 404

    user = User.query.get(report.user_id)
    if not user:
        return "User not found", 404

    chat_log_lines = report.chat_log.split('\n')
    return render_template('admin_view_chat_log.html', report=report, user=user, chat_log_lines=chat_log_lines)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

chat_flow = [
    "Hi! I'm your report assistant, Can you fully describe what happened?",
    "When did this happen? Please reply with the date.",
    "Please enter your contact number.",
    "Please upload evidence of the incident.",
    "Report received. Please type 'done' to finish."
]

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/test_url/<filename>')
def test_url(filename):
    try:
        file_url = url_for('uploaded_file', filename=filename)
        return f"URL: {file_url}"
    except Exception as e:
        return str(e)

@app.route('/test_template/<filename>')
def test_template(filename):
    return render_template('test_template.html', filename=filename)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables for all models
    app.run(debug=True)