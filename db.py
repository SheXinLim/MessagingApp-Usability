'''
db
database file, containing all the logic to interface with the sql database
'''

import base64
from sqlalchemy import create_engine, or_
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

# def hash_password(plain_password, salt=None):
#     if salt is None:
#         salt = os.urandom(16)  # Generate a new salt if none provided
#     hashed_password = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt, 100000)
#     salt_encoded = base64.b64encode(salt).decode('utf-8')
#     hashed_password_encoded = base64.b64encode(hashed_password).decode('utf-8')
#     return f"{salt_encoded}${hashed_password_encoded}"

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
        # Determine the role based on the username default admin is "admin"
        role = RoleType.ADMIN if username.lower() == "admin" else RoleType.STUDENT
        user = User(username=username, password=hashed_password, salt=salt, failed_attempts=0, lockout_until=None, role=role)
        session.add(user)
        session.commit()

# gets a user from the database
def get_user(username: str):
    with Session(engine) as session:
        return session.get(User, username)
    
# def remove_friend(username, friend_username):
#     with Session(engine) as session:
#         friendship = session.query(Friendship).filter((Friendship.user_id == username) & (Friendship.friend_id == friend_username)).first()
#         if friendship:
#             session.delete(friendship)
#             session.commit()
#             return True
#         return False

def remove_friend(username, friend_username):
    """
    Removes a friendship between two users, ensuring all bidirectional entries are deleted.

    :param username: The username of one user.
    :param friend_username: The username of the other user.
    :return: True if the friendship was successfully removed, False otherwise.
    """
    with Session(engine) as session:
        # Query and delete both possible directions of the friendship
        friendships = session.query(Friendship).filter(
            ((Friendship.user_id == username) & (Friendship.friend_id == friend_username)) |
            ((Friendship.user_id == friend_username) & (Friendship.friend_id == username))
        ).all()

        if friendships:
            for friendship in friendships:
                session.delete(friendship)
            session.commit()
            return True
        return False
    
def get_accepted_friend_request_id(user1_username, user2_username):
    """
    Retrieves the ID of an accepted friend request between two users, regardless of who was the sender or receiver.

    :param user1_username: The username of one of the users in the friend request.
    :param user2_username: The username of the other user in the friend request.
    :return: The ID of the accepted friend request if found, otherwise None.
    """
    with Session(engine) as session:
        # Query the friend_request table for an accepted entry matching the pair in either direction
        friend_request = session.query(FriendRequest).filter(
            or_(
                (FriendRequest.sender_username == user1_username) & (FriendRequest.receiver_username == user2_username),
                (FriendRequest.sender_username == user2_username) & (FriendRequest.receiver_username == user1_username)
            ),
            FriendRequest.status == 'accepted'  # Only select accepted friend requests
        ).first()

        # If an accepted friend request is found, return its ID
        if friend_request:
            return friend_request.id
        else:
            return None
        
def delete_friend_request_by_id(friend_request_id):
    """
    Deletes a friend request by its ID.

    :param friend_request_id: The ID of the friend request to be deleted.
    :return: True if the deletion was successful, False otherwise.
    """
    with Session(engine) as session:
        # Retrieve the friend request from the database by ID
        friend_request = session.get(FriendRequest, friend_request_id)

        if friend_request:
            session.delete(friend_request)
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

        if existing_request:
            # An existing friend request in a non-declined state is present, don't allow a new request
            return False

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

# admin can change role 
def update_user_role(username, role):
    with Session(engine) as session:
        try:
            user = session.query(User).filter_by(username=username).one_or_none()
            if user:
                # Check if the new role is different from the current role
                if user.role.value != role:
                    user.role = RoleType[role.upper()]  # Update the role, ensuring it's a valid enum value
                    session.commit()
                    return True  # Role was different and has been updated
                else:
                    return False  # Role is the same as the current role, no update needed
            else:
                return False  # User not found
        except:
            session.rollback()  # Roll back the transaction on error
            print(f"An error occurred")
            return False  # Return False on error

def get_all_users():
    with Session(engine) as session:
        return session.query(User).all()
    
#knowledge repository
def get_all_articles():
    with Session(engine) as session:
        articles = session.query(Article).all()
        return articles

def insert_article(title, content, username):
    with Session(engine) as session:
        user = session.get(User, username)  # Retrieve the user based on username
        loggedin_user = get_user(username)
        if loggedin_user.muted == True:
            return False, "You have been muted"

        if user:
            article = Article(title=title, content=content, author_id=username)
            session.add(article)
            session.commit()
            return True, "Article added successfully"
        return False, "User not found"

def update_article(article_id, title, content):
    with Session(engine) as session:
        article = session.get(Article, article_id)
        if article:
            article.title = title
            article.content = content
            session.commit()
            return True, "Article updated successfully"
        return False, "Article not found"

def delete_article(article_id):
    with Session(engine) as session:
        article = session.get(Article, article_id)
        if article:
            session.delete(article)
            session.commit()
            return True, "Article deleted successfully"
        return False, "Article not found"

def insert_comment(content, article_id, username):
    with Session(engine) as session:
        article = session.get(Article, article_id)
        user = session.get(User, username)
        loggedin_user = get_user(username)
        if loggedin_user.muted == True:
            return False, "You have been muted"
        if article and user:
            comment = Comment(content=content, article_id=article_id, author_id=username, author_role=user.role.name)
            session.add(comment)
            session.commit()
            return True, "Comment added successfully"
        return False, "Article or user not found"

def delete_comment_db(comment_id):
    with Session(engine) as session:
        comment = session.get(Comment, comment_id)
        if not comment:
            return False, "Comment not found"
        try:
            session.delete(comment)
            session.commit()
            return True, "Comment deleted successfully"
        except Exception as e:
            session.rollback()
            return False, f"An error occurred: {str(e)}"

def delete_comments_by_article_id(article_id):
    with Session(engine) as session:
        try:
            # Query to find all comments related to the article ID
            comments_to_delete = session.query(Comment).filter(Comment.article_id == article_id).all()
            for comment in comments_to_delete:
                session.delete(comment)
            session.commit()  # Commit the transaction to delete the records
            return True
        except Exception as e:
            session.rollback()  # Roll back the transaction on error
            print(f"Error deleting comments: {e}")
            return False
        finally:
            session.close()

def get_article(article_id):
    with Session(engine) as session:
        return session.query(Article).filter(Article.id == article_id).first()

def get_comments(article_id):
    with Session(engine) as session:
        return session.query(Comment).filter(Comment.article_id == article_id).all()
    
def get_user_role(username):
    with Session(engine) as session:
        user = session.query(User).filter(User.username == username).first()
        if user:
            return user.role.value
        else:
            return None  # Return None if the user is not found

def set_user_online(username, is_online):
    with Session(engine) as session:
        try:
            user = session.query(User).filter_by(username=username).one_or_none()
            if user:
                user.online = is_online
                session.commit()
                print(f"User {username} online status updated to {is_online}")
            else:
                print(f"No user found with username: {username}")
        except Exception as e:
            print(f"An error occurred: {e}")

def mute_user(username, mute_status):
    with Session(engine) as session:
        try:
            user = session.query(User).filter_by(username=username).one_or_none()
            if user:
                user.muted = mute_status
                session.commit()
                print(f"User {username} mute status updated to {mute_status}")
                return True
            else:
                print(f"No user found with username: {username}")
                return False
        except Exception as e:
            print(f"An error occurred: {e}")
            session.rollback()
            return False
        
def get_user_online(username):
    with Session(engine) as session:
        user = session.query(User).filter_by(username=username).first()
        if user:
            return user.online
        else:
            return None