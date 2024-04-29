'''
models
defines sql alchemy data models
also contains the definition for the room class used to keep track of socket.io rooms

Just a sidenote, using SQLAlchemy is a pain. If you want to go above and beyond, 
do this whole project in Node.js + Express and use Prisma instead, 
Prisma docs also looks so much better in comparison

or use SQLite, if you're not into fancy ORMs (but be mindful of Injection attacks :) )
'''

from sqlalchemy import String, Column, Integer, ForeignKey, Enum, DateTime
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from typing import Dict
from datetime import datetime

# data models
class Base(DeclarativeBase):
    pass

# model to store user information
class User(Base):
    __tablename__ = "user"
    
    # looks complicated but basically means
    # I want a username column of type string,
    # and I want this column to be my primary key
    # then accessing john.username -> will give me some data of type string
    # in other words we've mapped the username Python object property to an SQL column of type String 
    username: Mapped[str] = mapped_column(String, primary_key=True)
    password: Mapped[str] = mapped_column(String)
    salt: Mapped[str] = mapped_column(String)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    lockout_until: Mapped[datetime] = mapped_column(DateTime, nullable=True)

class FriendRequest(Base):
    __tablename__ = "friend_request"

    # Unique identifier for each friend request
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    
    # The sender of the friend request
    sender_username: Mapped[str] = mapped_column(String, ForeignKey('user.username'))
    
    # The recipient of the friend request
    receiver_username: Mapped[str] = mapped_column(String, ForeignKey('user.username'))
    
    # The status of the friend request (e.g., pending, accepted, declined)
    status: Mapped[str] = mapped_column(String)

    # Relationship with User model
    sender = relationship("User", foreign_keys=[sender_username])
    receiver = relationship("User", foreign_keys=[receiver_username])

class Friendship(Base):
    __tablename__ = "friendship"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey('user.username'))
    friend_id: Mapped[str] = mapped_column(String, ForeignKey('user.username'))

    user = relationship("User", foreign_keys=[user_id])
    friend = relationship("User", foreign_keys=[friend_id])

# stateful counter used to generate the room id
class Counter():
    def __init__(self):
        self.counter = 0
     
    def get(self):
        self.counter += 1
        return self.counter

# Room class, used to keep track of which username is in which room
class Room():
    def __init__(self):
        self.counter = Counter()
        # dictionary that maps the username to the room id
        # for example self.dict["John"] -> gives you the room id of 
        # the room where John is in
        self.dict: Dict[str, int] = {}

    def create_room(self, sender: str, receiver: str) -> int:
        room_id = self.counter.get()
        self.dict[sender] = room_id
        self.dict[receiver] = room_id
        return room_id
    
    def join_room(self,  sender: str, room_id: int) -> int:
        self.dict[sender] = room_id

    def leave_room(self, user):
        if user not in self.dict.keys():
            return
        del self.dict[user]

    # gets the room id from a user
    def get_room_id(self, user: str):
        if user not in self.dict.keys():
            return None
        return self.dict[user]
    
    def get_room_members(self, room_id: int):
        return {username for username, id_ in self.dict.items() if id_ == room_id}

    
    
   
class Message(Base):
    __tablename__ = "message"

    id = Column(Integer, primary_key=True)
    sender_username = Column(String, ForeignKey('user.username'))
    receiver_username = Column(String, ForeignKey('user.username'))
    content = Column(String)
    timestamp = Column(DateTime, default=datetime.now)


    sender = relationship("User", foreign_keys=[sender_username])
    receiver = relationship("User", foreign_keys=[receiver_username])

