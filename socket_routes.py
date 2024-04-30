'''
socket_routes
file containing all the routes related to socket.io
'''


from flask_socketio import join_room, emit, leave_room
from requests import Session
from flask import request
from db import engine
from sqlalchemy.orm import sessionmaker 

from hashlib import sha256
import hmac


try:
    from __main__ import socketio
except ImportError:
    from app import socketio

from models import Room, Message 

import db

room = Room()

Session = sessionmaker(bind=engine)


user_rooms = {}

user_messages = {}


user_left_status = {}

@socketio.on('connect')
def connect():
    username = request.cookies.get("username")
    room_id = request.cookies.get("room_id")
    if room_id is None or username is None:
        return

    join_room(room_id)

    with Session() as session:

        # Fetch messages sent by the user
        user_messages = session.query(Message).filter((Message.sender_username == username) | (Message.receiver_username == username)).all()
        for message in user_messages:
            emit("incoming", f"{message.sender_username}: {message.content}")

    emit("incoming", (f"{username} has connected", "green"), to=room_id)

    with Session() as session:
        session.add(Message(sender_username=username, content=f"{username} has connected"))
        session.commit()



@socketio.on('disconnect')
def disconnect():
    username = request.cookies.get("username")
    room_id = request.cookies.get("room_id")
    if room_id is None or username is None:
        return
    
    # Emit a message to inform the other user about the disconnection
    emit("incoming", (f"{username} has disconnected", "red"), to=room_id)
    
    # Leave the room
    leave_room(room_id)

    # Clear any data related to the conversation
    if username in room_relationships:
        del room_relationships[username]


    with Session() as session:
        session.add(Message(sender_username=username, content=f"{username} has disconnected"))
        session.commit()




joined_users = set()






room_relationships = {}


@socketio.on("join")
def join(sender_name, receiver_name):
    receiver = db.get_user(receiver_name)
    if receiver is None:
        return "Unknown receiver!"

    sender = db.get_user(sender_name)
    if sender is None:
        return "Unknown sender!"

    if receiver_name not in db.get_friends(sender_name):
        return "You can only join rooms with friends."

    room_id = room.get_room_id(receiver_name)

    if room_id is not None:
        room.join_room(sender_name, room_id)
        join_room(room_id)

        user_left_status[sender_name] = False
        
        # Add sender-receiver relationship to the room_relationships dictionary
        room_relationships.setdefault(sender_name, set()).add(receiver_name)
        
        # Emit to everyone in the room except the sender
        emit("incoming", (f"{sender_name} has joined the room.", "green"), to=room_id, include_self=False)
        # Emit only to the sender
        emit("incoming", (f"{sender_name} has joined the room. Now talking to {receiver_name}.", "green"))
        
        with Session() as session:
            session.add(Message(sender_username=sender_name, content=f"{sender_name} has joined the room. Now talking to {receiver_name}."))
            session.commit()

        

        joined_users.add(sender_name)
        return room_id

    # If the user isn't inside any room
    room_id = room.create_room(sender_name, receiver_name)
    join_room(room_id)

    
    # Add sender-receiver relationship to the room_relationships dictionary
    room_relationships.setdefault(sender_name, set()).add(receiver_name)
    
    emit("incoming", (f"{sender_name} has joined the room. Now talking to {receiver_name}.", "green"), to=room_id)

    with Session() as session:
        session.add(Message(sender_username=sender_name, content=f"{sender_name} has joined the room."))
        session.commit()

    

    joined_users.add(sender_name)
    return room_id




@socketio.on("send")
def send(username, message, room_id):
    if username not in joined_users:
        return "You must join a room before sending messages."
    
    room_members = room.get_room_members(room_id)
    if not room_members or username not in room_members:
        return "Both users must join the room before sending messages."
    
    # Check if the sender and receiver have joined the room with each other's usernames
    sender_name = username
    receiver_name = None
    for name, relationships in room_relationships.items():
        if sender_name in relationships:
            receiver_name = name
            break
    
    if receiver_name is None or sender_name not in room_relationships.get(receiver_name, set()):
        return "Both users must join the room with each other's usernames before sending messages."

    room_members = room.dict.values() 

    if len(room_members) > 1:
        # Emit the encrypted message to the room
        # emit("incoming", {"username": username, "message": message}, to=room_id)
        emit("incoming", f"{username}: {message}", to=room_id)


        # Check if the sender has left the room
        if user_left_status.get(username, False):
            return  # Don't store or emit the message if the sender has left the room
        



        with Session() as session:  # Create a session instance
            new_message = Message(sender_username=sender_name, receiver_username=receiver_name, content=message)
            session.add(new_message)
            session.commit()

            print(f"Encrypted message stored in the database: {username}: {message}")




@socketio.on("start_private_conversation")
def start_private_conversation(sender_name, receiver_name):
    room_id = room.create_room(sender_name, receiver_name)
    join_room(room_id)
    emit("private_conversation_started", room_id, room=room_id)

@socketio.on("private_message")
def private_message(username, message, room_id):
    emit("incoming", f"{username}: {message}", to=room_id)


# leave room event handler
@socketio.on("leave")
def leave(username, room_id):
    emit("incoming", (f"{username} has left the room.", "red"), to=room_id)
    
    user_left_status[username] = True

    with Session() as session:
        session.add(Message(sender_username=username, content=f"{username} has left the room."))
        session.commit()

    leave_room(room_id)
    room.leave_room(username)