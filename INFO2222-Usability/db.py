'''
db
database file, containing all the logic to interface with the sql database
'''

import base64
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import *

from pathlib import Path
import hashlib
import os

# creates the database directory
Path("database") \
    .mkdir(exist_ok=True)

# "database/main.db" specifies the database file
# change it if you wish
# turn echo = True to display the sql output
engine = create_engine("sqlite:///database/main.db", echo=False)

# initializes the database
Base.metadata.create_all(engine)

def hash_password(plain_password):
    salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt, 100000)
    salt_encoded = base64.b64encode(salt).decode('utf-8')
    hashed_password_encoded = base64.b64encode(hashed_password).decode('utf-8')
    return f"{salt_encoded}${hashed_password_encoded}"

def check_password(plain_password, stored_password):
    salt_encoded, hashed_password_encoded = stored_password.split('$')
    salt = base64.b64decode(salt_encoded)
    hashed_password = base64.b64decode(hashed_password_encoded)
    new_hashed_password = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt, 100000)
    return new_hashed_password == hashed_password

# Modify the insert_user function to hash password before storing
def insert_user(username: str, password: str, salt:str):
    with Session(engine) as session:
        hashed_password = hash_password(password)
        user = User(username=username, password=hashed_password, salt=salt, failed_attempts=0, lockout_until=None)
        session.add(user)
        session.commit()

# gets a user from the database
def get_user(username: str):
    with Session(engine) as session:
        return session.get(User, username)
    
def remove_friend(username, friend_username):
    with Session(engine) as session:
        friendship = session.query(Friendship).filter((Friendship.user_id == username) & (Friendship.friend_id == friend_username)).first()
        if friendship:
            session.delete(friendship)
            session.commit()
            return True
        return False

  
def send_friend_request(sender_username: str, receiver_username: str):
    with Session(engine) as session:
        # Check if both the sender and receiver exist in the database
        sender = session.query(User).filter_by(username=sender_username).first()
        receiver = session.query(User).filter_by(username=receiver_username).first()

        if not sender or not receiver:
            # sender or receiver doesn't exist
            return False

        # Prevent sending a friend request to oneself
        if sender_username == receiver_username:
            return False

        # Check if a friend request already exists between these two users
        existing_request = session.query(FriendRequest).filter(
            ((FriendRequest.sender_username == sender_username) & 
             (FriendRequest.receiver_username == receiver_username)) |
            ((FriendRequest.sender_username == receiver_username) & 
             (FriendRequest.receiver_username == sender_username))
        ).first()

        # If an existing request is found and it's declined, allow resending
        if existing_request and existing_request.status == 'declined':
            session.delete(existing_request)
            session.commit()
            existing_request = None

        # if existing_request:
        #     # An existing friend request in a non-declined state is present, don't allow a new request
        #     return False

        # If no existing request is found, or the declined one was removed, create a new friend request
        friend_request = FriendRequest(sender_username=sender_username, receiver_username=receiver_username, status='pending')
        session.add(friend_request)
        session.commit()
        return True

def get_friend_requests(username: str):
    with Session(engine) as session:
        # Fetching friend requests where the user is the receiver and the request is pending
        friend_requests = session.query(FriendRequest).filter_by(receiver_username=username, status='pending').all()
        return [fr.sender_username for fr in friend_requests]

def accept_friend_request(request_id: int, username: str):
    with Session(engine) as session:
        friend_request = session.get(FriendRequest, request_id)
        
        if not friend_request or friend_request.receiver_username != username:
            return False

        if friend_request.status == 'pending':
            friend_request.status = 'accepted'
            # Create the friendship in both directions
            user_id, friend_id = sorted([friend_request.sender_username, friend_request.receiver_username])

            # Check if the friendship already exists to prevent duplication
            existing_friendship = session.query(Friendship).filter_by(user_id=user_id, friend_id=friend_id).first()
            if not existing_friendship:
                session.add(Friendship(user_id=user_id, friend_id=friend_id))

            session.commit()
            return True
        
        return False

def decline_friend_request(request_id: int, username: str):
    with Session(engine) as session:
        friend_request = session.get(FriendRequest, request_id)
        
        if not friend_request or friend_request.receiver_username != username:
            return False

        if friend_request.status == 'pending':
            friend_request.status = 'declined'
            session.commit()
            return True
        
        session.commit()
        return False

def get_received_friend_requests(username: str):
    with Session(engine) as session:
        # Assuming FriendRequest model has 'receiver_username' and 'status' fields
        return session.query(FriendRequest).filter_by(receiver_username=username, status='pending').all()

def get_sent_friend_requests(username: str):
    with Session(engine) as session:
        # Assuming FriendRequest model has 'sender_username' and 'status' fields
        return session.query(FriendRequest).filter_by(sender_username=username, status='pending').all()
    
def get_friends(username: str):
    with Session(engine) as session:
        # Query the Friendship table for friendships involving the current user
        friendships = session.query(Friendship).filter(
            (Friendship.user_id == username) | (Friendship.friend_id == username)
        ).all()

        # Extract friend usernames
        friends = set()
        for friendship in friendships:
            # Add the friend's username, excluding the current user's username
            if friendship.user_id == username:
                friends.add(friendship.friend_id)
            else:
                friends.add(friendship.user_id)

        return list(friends)
    
def save_user(user):
    """
    Save or update user information in the database.
    """
    with Session(engine) as session:
        session.merge(user)  # The merge() method is used to either update an existing row or insert a new row.
        session.commit()


