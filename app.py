from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['TEMPLATES_AUTO_RELOAD'] = True  # Add this line
db = SQLAlchemy(app)

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
    user = User.query.get(user_id)
    reports = Report.query.filter_by(user_id=user_id).order_by(Report.date.desc()).all()
    return render_template('user_dashboard.html', user=user, reports=reports)

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    current_user = User.query.get(user_id)
    if not current_user.is_admin:
        return redirect(url_for('login'))

    reports = Report.query.order_by(Report.date.desc()).all()
    return render_template('admin_dashboard.html', reports=reports)

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

@app.route('/view_chat_log/<int:report_id>')
def view_chat_log(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    report = Report.query.get(report_id)
    if not report:
        return "Report not found", 404

    user = User.query.get(report.user_id)
    if not user:
        return "User not found", 404

    current_user = User.query.get(session['user_id'])

    chat_log_lines = report.chat_log.split('\n')

    if current_user.is_admin:
        return render_template('view_chat_log.html', report=report, user=user, chat_log_lines=chat_log_lines)
    else:
        if report.user_id != current_user.id:
            return "Unauthorized access", 403
        return render_template('user_view_chat_log.html', report=report, user=user, chat_log_lines=chat_log_lines)

chat_flow = [
    "What type of Cybercrime are you reporting?",
    "Can you explain in full details?",
    "Please provide your contact number?",
    "Thank you for reporting, please type done to confirm."
]

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        user_input = request.form['user_input']
        session['chat_log'].append(f"User: {user_input}")

        if session['chat_state'] < len(chat_flow):
            response = chat_flow[session['chat_state']]
            session['chat_state'] += 1
            session['chat_log'].append(f"Bot: {response}")
        else:
            response = "Thank you for the information. Your report has been submitted."
            new_report = Report(user_id=session['user_id'], chat_log='\n'.join(session['chat_log']))
            db.session.add(new_report)
            db.session.commit()
            session.pop('chat_state')
            session.pop('chat_log')
            return redirect(url_for('user_dashboard'))

        return render_template('report.html', chat_log=session['chat_log'], response=response)
    
    if 'chat_state' not in session:
        session['chat_state'] = 0
        session['chat_log'] = []
        response = chat_flow[session['chat_state']]
        session['chat_log'].append(f"Bot: {response}")
        session['chat_state'] += 1
    else:
        response = chat_flow[session['chat_state']]

    return render_template('report.html', chat_log=session['chat_log'], response=response)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(email='admin@example.com').first():
            admin_user = User(
                fullname='Admin User',
                email='admin@example.com',
                password=generate_password_hash('159369258', method='pbkdf2:sha256'),
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()

    app.run(debug=True)