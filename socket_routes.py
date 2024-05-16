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
    try:
        db.set_user_online(username, True)
        print(f"Debug: Set {username} online.")  # Debug print
    except Exception as e:
        print(f"Debug: Error setting user online: {e}")  # Debug print

    room_id = request.cookies.get("room_id")
    if room_id is None or username is None:
        return

    join_room(room_id)
    with Session() as session:

        # Fetch messages sent by the user
        user_messages = session.query(Message).filter((Message.sender_username == username) | (Message.receiver_username == username)).all()


        server_messages = [
            f"{username} has connected",
            f"{username} has disconnected",
            f"{username} has left the room.",
            f"{username} has joined the room."
        ]

        for message in user_messages:
            if message.content in server_messages:
                emit("incoming", message.content, to=room_id)
            elif "has joined the room. Now talking to" in message.content:
                emit("incoming", message.content, to=room_id)
            else: 
                emit("incoming", f"{message.sender_username}: {message.content}")

    emit("incoming", (f"{username} has connected", "green"), to=room_id)

    with Session() as session:
        session.add(Message(sender_username=username, content=f"{username} has connected"))
        session.commit()

@socketio.on('disconnect')
def disconnect():
    username = request.cookies.get("username")
    try:
        db.set_user_online(username, False)
        print(f"Debug: Set {username} offline.")  # Debug print
    except Exception as e:
        print(f"Debug: Error setting user offline: {e}")  # Debug print
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
    sender = db.get_user(sender_name)
    if sender and sender.muted:
        emit("error", {"success": False, "message": "You have been muted and cannot join the room."})
        return
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
# def send(username, receiver, message, room_id):
    if username not in joined_users:
        return "You must join a room before sending messages."

    # Check if the sender or receiver have joined the room
    room_members = room.get_room_members(room_id)
    
    
    # Get the receiver's username
    receiver_name = None
    for name in room_members:
        if name != username:
            receiver_name = name
            break

        
    if not room_members or username not in room_members:
        #message only to the sender's room
        emit("incoming", f"{username}: {message}")

        print(f"this is happening whats up?")

        with Session() as session:  # Create a session instance
            new_message = Message(sender_username=username, receiver_username=receiver_name, content=message)
            session.add(new_message)
            session.commit()

        print(f"this is happening -  {username}: {message}")

        return


    # Check if the sender has left the room
    if user_left_status.get(username, False):
        return  # Don't store or emit the message if the sender has left the room
    

    # Emit the message to the room
    emit("incoming", f"{username}: {message}", to=room_id)

    
    with Session() as session:  # Create a session instance
        new_message = Message(sender_username=username, receiver_username=receiver_name, content=message)
        session.add(new_message)
        session.commit()

        print(f"Encrypted message stored in the database: {username}: {message}")



# @socketio.on("delete_message")
# def delete_message(data):
#     print("Received delete message request")
#     message_content = data.get("message")
#     print("Message content to delete:", message_content)

#     separator_index = message_content.find(": ")

#     if separator_index != -1:
#         new_variable = message_content[separator_index + 2:]
#         print("Extracted content:", new_variable)
#     else:
#         print("Colon and space (': ') not found in message content")

#     try:
#         with Session() as session:
        
#             message = session.query(Message).filter(Message.content == new_variable).first()

#             if message:
#                 print("deleting")
#                 session.delete(message)
#                 session.commit()
#                 print("Message deleted successfully")
#                 emit("message_deleted", message_content, broadcast=True)
#             else:
#                 print("Message not found in the database")
#     except Exception as e:
#         print("Error deleting message from database:", e)
#         session.rollback()
        
@socketio.on("delete_message")
def delete_message(data):
    print("Received delete message request")
    message_content = data.get("message")
    print("Message content to delete:", message_content)

    separator_index = message_content.find(": ")

    if separator_index != -1:
        content_to_delete = message_content[separator_index + 2:]
        print("Extracted content:", content_to_delete)
    else:
        print("Colon and space (': ') not found in message content")
        return

    # Get the sender's username from the request context
    sender_username = request.cookies.get("username")

    try:
        with Session() as session:
            # Query the message based on its content
            message = session.query(Message).filter(Message.content == content_to_delete).first()

            if message:

                # Check if the message belongs to the sender making the delete request
                if message.sender_username == sender_username:
                    session.delete(message)
                    session.commit()
                    print("Message deleted successfully")
                    emit("message_deleted", message_content, broadcast=True)
                else:
                     print("This is not deleted in message history, you are not sender.")
                     emit("incoming", (f"You are not the sender, message still in message history.", "red"))
            else:
                print("Message not found in the database")
    except Exception as e:
        print("Error deleting message from database:", e)
        session.rollback()



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