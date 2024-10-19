from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'
socketio = SocketIO(app)
login_manager = LoginManager(app)

users = {}  # Store users
messages = []  # Store messages
private_chats = {}  # Store private messages

class User(UserMixin):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def get_id(self):
        return self.username

@login_manager.user_loader
def load_user(username):
    return users.get(username)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = users.get(username)

    if user and check_password_hash(user.password, password):
        login_user(user)
        return redirect(url_for('chat'))
    return 'Invalid credentials', 401

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users:
            return 'User already exists', 400
        
        users[username] = User(username, generate_password_hash(password))
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', messages=messages, username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@socketio.on('message')
def handle_message(data):
    msg = data['message']
    sender = data['sender']
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    messages.append({'msg': msg, 'sender': sender, 'timestamp': timestamp})
    emit('message', {'msg': msg, 'sender': sender, 'timestamp': timestamp}, broadcast=True)

@socketio.on('private_message')
def handle_private_message(data):
    recipient = data['recipient']
    msg = data['message']
    sender = data['sender']
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if recipient not in private_chats:
        private_chats[recipient] = []
    private_chats[recipient].append({'msg': msg, 'sender': sender, 'timestamp': timestamp})
    
    emit('private_message', {'msg': msg, 'sender': sender, 'timestamp': timestamp}, room=recipient)

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
