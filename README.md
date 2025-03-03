

# **MessagingApp**

## **Overview**
This project is a end-to-end (E2E) secure messaging app providing website support system for undergraduate students at the School of Computer Science, University of Sydney. The platform enables students to share experiences, seek academic help, and contribute to a knowledge repository of useful study materials.

Main features include **real-time secure messaging**, a **friends system**, **chatroom** support for more than two users, a **knowledge repository** for posts, and a comment system similar to a forum.

The main technology driving this application is socket.io, which allows two-way real-time communication between the client and server through "socket events." The system includes a messaging and friends system, along with features to improve usability, collaboration, and role-based access control.

---

## **🚀 Installation & Setup**
### **1. Install Required Packages**
Ensure you have Python and the necessary dependencies installed. Run:

```bash
pip install SQLAlchemy flask-socketio simple-websocket
```

### **2. Run the Application**
After installing dependencies, start the application with:
```sh
python3 app.py
```

### **3. Access the Application**
Once running, open a browser and go to:
```
http://127.0.0.1:5000
```

---

## **🌟 Features**
### **Messaging & Friends List Enhancements**
- **Enhanced UI/UX** for better usability.
- **Friends list improvements**:
  - Shows **online/offline status** and **account role** (Student, Staff, etc.).
  - Ability to **remove friends**.
- **Offline Messaging Support**:
  - Messages sent while offline will be **stored** and loaded upon next login.

### **Knowledge Repository**
A shared space for students and staff to **contribute and discuss academic materials**.
- **Users can create and edit articles**.
- **Staff can delete or modify all articles**.
- **Commenting system**:
  - Students and staff can **comment on articles**.
  - Staff can **delete inappropriate comments**.
- **User moderation**:
  - Staff can **mute/unmute users**, restricting their ability to post or chat.
  
### **Group Chat & Chatroom Features**
- Chatrooms now support **more than 2 users**, enabling group discussions.

### **Role-Based Access Control**
- Users have different **permissions** based on their role:
  - **Student**
  - **Staff** (Academics, Administrative Staff, Admin)
- Role is displayed in **profiles and posts**.


### **Additional Features**
- Custom **user function** based on **user research findings**.

---

## **🔍 Technical Overview**
### **Tech Stack**
#### **Backend**
- **Python**
- Flask
- **Flask-SocketIO** for real-time communication
- **SQLAlchemy** (Database ORM)
- **Jinja2** (Template engine)

#### **Frontend**
- **HTML, CSS, JavaScript**
- **Socket.io** (real-time messaging)
- **Axios & jQuery** (AJAX requests)
- **Bootstrap** (for responsive UI)


#### Javascript Dependencies
- Socket.io
- Axios (for sending post requests, but a bit easier than using fetch())
- Cookies (small browser library that makes working with cookies just a bit easier)

#### Python Dependencies
- Template Engine: Jinja
- Database ORM: SQL Alchemy
- Flask Socket.io
---

## **📝 Usage Instructions**
1. Open the app in **two different browsers** (e.g., Chrome & Firefox).
2. **Sign up or log in** with different usernames.
3. Use the **messaging feature** to chat with others.
4. Explore the **knowledge repository** and **chatrooms**.

---




⚠️ A Warning  
Since this app **uses cookies for session management**, you **cannot** test multiple users by opening new tabs in the same browser, as cookies are shared across tabs.  
To properly test multi-user communication, use **different browsers** (e.g., Chrome & Firefox) or **incognito/private mode** in separate windows.


