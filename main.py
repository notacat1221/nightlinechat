from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt


app = Flask(__name__)
socketio = SocketIO(app, ssl_context=('adhoc')) #enable SSL, 'adhoc' self signs the certificate
app.config['SECRET_KEY'] = 'byallknownlawsofaviationbeesshouldnotbeabletofly'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_BINDS'] = {'MessageRecord': 'sqlite:///msghistory.db'}
usersDB = SQLAlchemy(app)
roomsList = []

class User(usersDB.Model):
    id = usersDB.Column(usersDB.Integer, primary_key=True)
    username = usersDB.Column(usersDB.String(20), unique=True, nullable=False)
    password = usersDB.Column(usersDB.String(40), nullable=False)
    userType = usersDB.Column(usersDB.String(20), nullable=False)
class MessageRecord(usersDB.Model):
    __bind_key__ = 'MessageRecord' # binds class to msghistory
    id = usersDB.Column(usersDB.Integer, primary_key=True)
    content = usersDB.Column(usersDB.String(255), nullable=False)
    sender = usersDB.Column(usersDB.String(20), nullable=False)
    room = usersDB.Column(usersDB.String(8), nullable=False)


@app.route('/')
def index():
    flash('')
    currentUser = session.get('username')
    if currentUser == None:
        return redirect(url_for('login'))
    return render_template('index.html', currentUser=currentUser, roomsList=roomsList)


def get_messages(room, username):
    roomMessageHistory = MessageRecord.query.filter_by(room=room).all()
    # For each record in roomMessageHistory, emit to new user
    for message in roomMessageHistory:
        if message.sender != 'System':
            socketio.emit('message', {'sender': message.sender, 'content': message.content}, room=request.sid)
    socketio.emit('message', {'sender': 'System', 'content': (username, 'has joined the room.')}, room=room)
    
    
@app.route('/get_rooms')
def get_rooms():
    global roomsList
    rooms = []
    # Parse roomsList and take all from rooms field
    for record in roomsList:
        rooms.append(record['room'])
    print(rooms)
    return jsonify(rooms)
    socketio.emit('sendRoomsList', rooms, room=request.sid)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        userType = 'student'
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
        elif username == '' or password == '':
            flash('Username and password cannot be empty')
        else:
            passHash = sha256_crypt.hash(password)
            newUser = User(username=username, password=passHash, userType=userType)
            usersDB.session.add(newUser)
            usersDB.session.commit()
            flash('Account successfully created. You may now log in.')
            return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')


        user = User.query.filter_by(username=username).first()
        if user:
            if sha256_crypt.verify(password, user.password):
                session['username'] = username #store username for currently logged user in session
                session['userType'] = user.userType
                return redirect(url_for('index'))
            else:
                flash('Password is incorrect, please try again')
        else:
            flash('Username is incorrect, please try again')
    return render_template('login.html')


@app.route('/logout')
def logout():
    global roomsList
    username = session['username']
    roomsList = [record for record in roomsList if record['username'] != username]
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/viewusers')
def view_users():
    if 'username' not in session:
        return redirect(url_for('login'))
    if (session['userType'] == 'administrator'):
        users = User.query.all()
        return render_template('viewUsers.html', users=users)
    else:
        return redirect(url_for('index'))


@app.route('/viewmessagehistory')
def view_message_history():
    if 'username' not in session:
        return redirect(url_for('login'))
    if(session['userType'] == 'administrator'):
        messages = MessageRecord.query.all()
        return render_template('viewMessageHistory.html', messages=messages)
    else:
        return redirect(url_for('index'))

@socketio.on('join')
def handle_connect(data):
    if(session['userType'] == 'student'):
        room = data['username']
    else:
        room = data['room']
    username = data['username']

    join_room(room)
    print(username,"joined room:",room)
    get_messages(room, username)
    emit('room_assigned', {'room': room}, room=room)


@socketio.on('requestCurrentRoom')
def handle_request_current_room(data):
    username = data['username']
    for record in roomsList:
        if record['username'] == username:
            room = record['room']
            socketio.emit('current_room', {'room': room}, room=request.sid)

@socketio.on('assignStudentRoom')
def handle_assign_student_room(data):
    room = data['username']
    username = data['username']
    join_room(room)
    session['room'] = room
    get_messages(room, username)
    print("serverside session value:",session['room'])
    emit('room_assigned', {'room': room}, room=request.sid)
    print(username,"assigned to room:",room)
    roomRecord = {
        'room': room,
        'username': username
    }
    global roomsList
    roomsList = [record for record in roomsList if record['room']!=room and record['username']!=username]
    roomsList.append(roomRecord)
    get_rooms()
    print(roomsList)


@socketio.on('leave')
def handle_disconnect(messagedata):
    username = 'user'
    room = messagedata['room']
    leave_room(room)
    message = {'sender': 'System', 'content': (username + " has connected to room")}
    socketio.emit('message', message, room=room)

@socketio.on('message')
def handle_message(incomingmessage):
    print('Received message:', incomingmessage)
    #Unpack incomingMessage into variables
    content = incomingmessage['content']
    room = incomingmessage['room']
    sender = incomingmessage['sender']

    #Store message in message history sql table
    storeMessage = MessageRecord(content=content, sender=sender, room=room)
    usersDB.session.add(storeMessage)
    usersDB.session.commit()

    #Push message to connected clients
    messageData = {'content': incomingmessage['content'], 'room': room, 'sender': sender}
    socketio.emit('message', messageData, room=room)

if __name__ == '__main__':
    with app.app_context():
        usersDB.create_all()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
