import os
from datetime import datetime, timedelta
import re
import time
from collections import defaultdict

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import SQLAlchemyError

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get the directory of the current script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'instance', 'chat.db')

# Ensure the directory exists
os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {
        'check_same_thread': False,
    }
}
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_NAME'] = 'chat_session'
app.config['SESSION_COOKIE_SECURE'] = True  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
socketio = SocketIO(app, manage_session=False)
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
login_manager.login_view = 'login'
active_users = defaultdict(int)  # Store user_id: last_active_timestamp
OFFLINE_THRESHOLD = 30  # Seconds until user is considered offline


# Validation functions
def validate_username(username):
    return bool(re.match(r'^[\w\d_]{3,20}$', username))


def validate_email(email):
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))


def validate_password(password):
    return len(password) >= 8


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('message.id'),nullable=True)
    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'reply_to' : None
        }
        if self.reply_to_id:
            replied_message = Message.query.get(self.reply_to_id)
            if replied_message:
                data['reply_to']={
                    'id': replied_message.id,
                    'content': replied_message.content,
                    'senderName': User.query.get(replied_message.sender_id).username
                }


        return data


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Session validation middleware
@app.before_request
def validate_session():
    if current_user.is_authenticated:
        if 'user_id' not in session or session.get('user_id') != current_user.id:
            logout_user()
            session.clear()
            flash('Your session has expired. Please login again.')
            return redirect(url_for('login'))

        login_time = session.get('login_time', 0)
        if datetime.utcnow().timestamp() - login_time > app.config['PERMANENT_SESSION_LIFETIME'].total_seconds():
            logout_user()
            session.clear()
            flash('Your session has expired. Please login again.')
            return redirect(url_for('login'))


# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/get_online_users')
@login_required
def get_online_users():
    current_time = time.time()
    online_users = []
    for user_id in active_users:
        if current_time - active_users[user_id] < OFFLINE_THRESHOLD:
            online_users.append(user_id)
    return {'online_users': online_users}

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not all([username, email, password]):
            flash('All fields are required.')
            return redirect(url_for('register'))

        if not validate_username(username):
            flash('Username must be 3-20 characters long and contain only letters, numbers, and underscores.')
            return redirect(url_for('register'))

        if not validate_email(email):
            flash('Invalid email format.')
            return redirect(url_for('register'))

        if not validate_password(password):
            flash('Password must be at least 8 characters long.')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)

        try:
            db.session.commit()
            flash('Registration successful!')
            return redirect(url_for('login'))
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error during registration: {str(e)}")
            flash('An error occurred during registration. Please try again.')
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("30 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Both username and password are required.')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session.clear()
            session.permanent = True
            login_user(user)
            session['user_id'] = user.id
            session['login_time'] = datetime.utcnow().timestamp()

            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('chat'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    user_id = current_user.id
    session.clear()
    logout_user()
    socketio.emit('force_disconnect', room=f"user_{user_id}")
    return redirect(url_for('login'))


@app.route('/chat')
@login_required
def chat():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('chat.html', users=users)


@app.route('/get_messages/<int:other_user_id>')
@login_required
def get_messages(other_user_id):
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == other_user_id)) |
        ((Message.sender_id == other_user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    return {
        'messages': [
            {
                **message.to_dict(),
                'sender_username': User.query.get(message.sender_id).username
            }
            for message in messages
        ]
    }


# SocketIO event handlers
@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        return False

    if 'user_id' not in session or session.get('user_id') != current_user.id:
        return False

    join_room(f"user_{current_user.id}")
    active_users[current_user.id] = time.time()

    # Broadcast to all users that this user is online
    emit('user_status_change', {
        'user_id': current_user.id,
        'status': 'online'
    }, broadcast=True)

    emit('status', {
        'user_id': current_user.id,
        'username': current_user.username,
        'msg': f'{current_user.username} has connected'
    })


@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(f"user_{current_user.id}")
        if current_user.id in active_users:
            del active_users[current_user.id]

        # Broadcast to all users that this user is offline
        emit('user_status_change', {
            'user_id': current_user.id,
            'status': 'offline'
        }, broadcast=True)

        emit('status', {
            'user_id': current_user.id,
            'username': current_user.username,
            'msg': f'{current_user.username} has disconnected'
        })

# Add new heartbeat event handler to keep track of active users
@socketio.on('heartbeat')
def handle_heartbeat():
    if current_user.is_authenticated:
        active_users[current_user.id] = time.time()


@socketio.on('typing')
def handle_typing(data):
    if not current_user.is_authenticated:
        return

    receiver_id = data.get('receiver_id')
    if receiver_id:
        emit('typing', {
            'sender_id': current_user.id
        }, room=f"user_{receiver_id}")


@socketio.on('stop_typing')
def handle_stop_typing(data):
    if not current_user.is_authenticated:
        return

    receiver_id = data.get('receiver_id')
    if receiver_id:
        emit('stop_typing', {
            'sender_id': current_user.id
        }, room=f"user_{receiver_id}")

@socketio.on('send_message')
def handle_message(data):
    if not current_user.is_authenticated:
        emit('error', {'msg': 'Authentication required'})
        return

    content = data.get('message')
    receiver_id = data.get('receiver_id')

    if not content or not receiver_id:
        emit('error', {'msg': 'Invalid message data'})
        return

    try:
        message = Message(
            content=content,
            sender_id=current_user.id,
            receiver_id=receiver_id
        )
        db.session.add(message)
        db.session.commit()

        message_data = {
            'message': message.to_dict(),
            'sender_username': current_user.username
        }

        emit('new_message', message_data, room=f"user_{current_user.id}")
        emit('new_message', message_data, room=f"user_{receiver_id}")

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error while sending message: {str(e)}")
        emit('error', {'msg': 'Failed to send message'})


@socketio.on_error_default
def default_error_handler(e):
    app.logger.error(f"SocketIO Error: {str(e)}")
    emit('error', {'msg': 'An error occurred'})


# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


# Context processor
@app.context_processor
def utility_processor():
    def get_user_name(user_id):
        user = User.query.get(user_id)
        return user.username if user else "Unknown User"

    return dict(get_user_name=get_user_name)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)