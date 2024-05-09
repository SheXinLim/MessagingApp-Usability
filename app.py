'''
app.py contains all of the server application
this is where you'll find all of the get/post request handlers
the socket event handlers are inside of socket_routes.py
'''
from flask import Flask, flash, jsonify, redirect, render_template, request, abort, session, url_for
from flask_socketio import SocketIO
import db
import secrets
import ssl
from datetime import datetime
from datetime import timedelta
from enum import Enum
import hashlib
import logging
# # #this turns off Flask Logging, uncomment this to turn off Logging
# log = logging.getLogger('werkzeug')
# log.setLevel(logging.ERROR)

def csp_policy_string(policy_dict):
    return "; ".join([f"{key} {' '.join(val) if isinstance(val, list) else val}" for key, val in policy_dict.items()])

app = Flask(__name__)
@app.after_request
def apply_csp(response):
    policy = {
    "default-src": "'self'",
    "script-src": [
        "'self'",
        "https://cdnjs.cloudflare.com",  # Allow scripts from CDN for Crypto-JS
        "https://cdn.jsdelivr.net",
        "'unsafe-inline'" 
    ],
    "style-src": "'self' 'unsafe-inline'",  # Allows inline styles;
    "img-src": "'self'",
    "connect-src": "'self'",  # Restricts the URLs which can be loaded using script interfaces
    "font-src": "'self'",  # Fonts loading
    "object-src": "'none'",  # Prevents object, embed, and applet elements from rendering
    "frame-ancestors": "'none'"  # Protects against clickjacking
}

    response.headers['Content-Security-Policy'] = csp_policy_string(policy)
    return response


# secret key used to sign the session cookie
app.config['SECRET_KEY'] = secrets.token_hex()
socketio = SocketIO(app)

# don't remove this!!
import socket_routes

# index page
@app.route("/")
def index():
    return render_template("index.jinja")

# login page
@app.route("/login")
def login():    
    return render_template("login.jinja")


@app.route("/login/user", methods=["POST"])
def login_user():
    if not request.is_json:
        abort(404)

    username = request.json.get("username")
    password = request.json.get("password")
    user = db.get_user(username)

    if user is None:
        return jsonify({"error": "User does not exist!"})

    # Check if account is currently locked
    if user.lockout_until and datetime.now() < user.lockout_until:
        return jsonify({"error": "Account is locked. Please try again later."})

    if not db.check_password(password, user.password):
        user.failed_attempts += 1
        if user.failed_attempts >= 3:
            user.lockout_until = datetime.now() + timedelta(minutes=30)
            db.save_user(user)
            return jsonify({"error": "Account is locked. Please try again in 30 minutes."})
        db.save_user(user)
        return jsonify({"error": "Password does not match!"})

    # Reset failed attempts on successful login
    user.failed_attempts = 0
    user.lockout_until = None
    db.save_user(user)
    session['username'] = username
    return jsonify({"redirect": url_for('home', username=username)})

# handles a get request to the signup page
@app.route("/signup")
def signup():
    return render_template("signup.jinja")

# handles a post request when the user clicks the signup button
@app.route("/signup/user", methods=["POST"])
def signup_user():
    if not request.is_json:
        abort(404)
    username = request.json.get("username")
    password = request.json.get("password")
    salt = request.json.get("salt")

    if not username or not password:
        return "Error: Username and password are required."

    if db.get_user(username) is not None:
        # return "Error: User already exists!"
        return jsonify({"error": "User already exists!"})
    else:
        db.insert_user(username, password, salt)
        session['username'] = username  # Automatically log in the user after signup
        # return url_for('home', username=username)
        return jsonify({"redirect": url_for('home', username=username)})
# handler when a "404" error happens
@app.errorhandler(404)
def page_not_found(_):
    return render_template('404.jinja'), 404


# home page, where the messaging app is
@app.route("/home")
def home():
    username = request.args.get("username") or session.get("username")
    if username is None:
        abort(404)
    received_requests = db.get_received_friend_requests(username)
    sent_requests = db.get_sent_friend_requests(username)
    friends = db.get_friends(username)  # Get the list of friends
    user = db.get_user(username)
    friends_roles = []  # Initialize an empty list for friend roles
    friend_online =[ ]
    
    for friend in friends:
        role = db.get_user_role(friend)
        friends_roles.append(role)

    for friend in friends:
        online  = db.get_user_online(friend)
        friend_online.append(online)

    #Convert enum to string here
    user_role = user.role.name if hasattr(user.role, 'name') else str(user.role)

    return render_template("home.jinja", username=username, received_requests=received_requests, 
                           sent_requests=sent_requests, friends=list(zip(friends, friends_roles, friend_online)), user_role=user_role)


# friend req
@app.route("/send-friend-request", methods=["POST"])
def send_friend_request_route():
    if not request.is_json:
        abort(400)

    sender_username = session.get("username")  # Assume the sender is the logged-in user
    receiver_username = request.json.get("receiver")

    if not sender_username:
        return "You must be logged in to send friend requests"

    if db.send_friend_request(sender_username, receiver_username):
        return "Friend request sent successfully!"
    else:
        return "Friend request could not be sent (user may not exist or you guys are already friends)"
    
@app.route('/friend-requests')
def friend_requests():
    username = session.get('username')
    if not username:
        flash('You need to login first.')
        return redirect(url_for('login'))

    received_requests = db.get_received_friend_requests(username)
    sent_requests = db.get_sent_friend_requests(username)

    # Convert FriendRequest objects to dictionaries
    received_requests_data = [{'sender_username': req.sender_username, 'id': req.id} for req in received_requests]
    sent_requests_data = [{'receiver_username': req.receiver_username, 'id': req.id} for req in sent_requests]

    return render_template('friend_requests.jinja', 
                           received_requests=received_requests_data, 
                           sent_requests=sent_requests_data,
                           username=username)

@app.route("/accept-friend-request/<request_id>", methods=["POST"])
def accept_friend_request_route(request_id):
    username = session.get("username")  # Get username from session
    if not username:
        return "You must be logged in to accept friend requests", 403

    if db.accept_friend_request(int(request_id),username):
        return jsonify(message="Friend request accepted!") 
    else:
        return jsonify(message="Relog and try again") 
    
@app.route("/decline-friend-request/<request_id>", methods=["POST"])
def decline_friend_request_route(request_id):
    username = session.get("username")  # Get username from session
    if not username:
        return "You must be logged in to decline friend requests", 403

    success = db.decline_friend_request(int(request_id), username)
    if success:
        return jsonify(message="Friend request declined successfully") 
    else:
        return jsonify(message="Relog and try again")
    
@app.route('/logout')
def logout():
    session.clear()  # Clear all data from the session
    flash('You have been logged out.')
    return redirect(url_for('login'))  # Redirect to the login page or home page

@app.route('/api/friend-requests')
def api_friend_requests():
    username = session.get('username')
    if not username:
        return jsonify({'error': 'User not logged in'}), 403

    received_requests = db.get_received_friend_requests(username)
    sent_requests = db.get_sent_friend_requests(username)

    # Convert FriendRequest objects to dictionaries
    received_requests_data = [{'sender_username': req.sender_username, 'id': req.id} for req in received_requests]
    sent_requests_data = [{'receiver_username': req.receiver_username, 'id': req.id} for req in sent_requests]

    return jsonify({
        'received_requests': received_requests_data,
        'sent_requests': sent_requests_data
    })


@app.route('/api/friends-list')
def get_friends_list():
    username = session.get('username')
    if not username:
        return jsonify({'error': 'Not logged in'}), 403
    friends = db.get_friends(username)  # This should return a list of friend usernames
    friends_roles = []  # Initialize an empty list for friend roles
    friends_online = []
    
    # Assuming you have a function to get roles for each friend
    for friend in friends:
        role = db.get_user_role(friend)
        friends_roles.append(role)

      # Assuming you have a function to get roles for each friend
    for friend in friends:
        online = db.get_user_online(friend)
        friends_online.append(online)


    return jsonify({'friends': list(zip(friends, friends_roles, friends_online))})

@app.route('/get_salt', methods=['POST'])
def get_salt():
    username = request.json.get('username')
    user = db.get_user(username)
    if user:
        return jsonify({'salt': user.salt}) 
    else:
        return jsonify({'error': 'User not found'}), 404
    
@app.route("/get-hashed-password/<username>")
def get_hashed_password(username):
    user = db.get_user(username)
    if user:
        return jsonify({"hashed_password": user.password})
    else:
        return jsonify({"error": "User not found"}), 404   

@app.route('/remove-friend/<friend_username>', methods=['POST'])
def remove_friend(friend_username):
    username = session.get('username')  # Retrieve the current user from the session
    if not username:
        return jsonify({'error': 'You must be logged in to perform this action.'}), 403

    # Remove the friend entirely
    friend_removed = db.remove_friend(username, friend_username)
    if not friend_removed:
        return jsonify({'error': 'Failed to remove friend.'}), 400
    
    # Attempt to retrieve the friend request ID
    friendreq_id = db.get_accepted_friend_request_id(username, friend_username)

    if friendreq_id is None:
        return jsonify({'error': 'Failed to retrieve friend request ID.'}), 401
    
    # Attempt to delete the friend request by ID
    request_deleted = db.delete_friend_request_by_id(friendreq_id)
    if not request_deleted:
        return jsonify({'error': 'Failed to delete friend request.'}), 500

    return  jsonify(message="Friend has been removed"), 200

@app.route('/user/profile/<username>')
def user_profile(username):
    user = db.get_user(username)  # Retrieve the user by username from the database
    if not user:
        flash("User not found", "error")
        return redirect(url_for('index'))  # Redirects to a generic index or error page if user not found
    # Pass the entire user object to the template which allows us to access all attributes of the user
    return render_template("user_profile.jinja", user=user)

def sha256_hash(salted_password):
    hash_object = hashlib.sha256(salted_password.encode('utf-8'))
    hashed_password = hash_object.hexdigest()  # Convert hash to hexadecimal string
    return hashed_password

def create_default_admin():
    admin_username = 'admin'
    admin_password = 'Info2222-AdminSecurePw!'
    admin_salt = 'GYNQNPCXCLJkl0dI'
    saltPassword = admin_password + admin_salt
    hashedPassword = sha256_hash(saltPassword)

    # Check if user already exists
    user = db.get_user(admin_username)
    if user is None:
        with app.test_client() as client:
            response = client.post('/signup/user', json={
                'username': admin_username,
                'password': hashedPassword,
                'salt': admin_salt
            })
            print(response.json)  # To see what the response is


@app.route('/admin-panel')
def admin_panel():
    # Optional: Check if the user is logged in and is an admin
    username = session.get('username')
    if not username:
        flash('You must be logged in to access the admin panel.')
        return redirect(url_for('login'))

    user = db.get_user(username)
    #Convert enum to string here
    user_role = user.role.name if hasattr(user.role, 'name') else str(user.role)

    if user is None or user_role != 'ADMIN':
        flash('You do not have permission to access the admin panel.')
        return redirect(url_for('home'))
    
    print("User Role:", user.role)  # Print the enum or string directly
    users = db.get_all_users()
    # Render an admin panel template or return relevant data
    return render_template('admin_panel.jinja', username=username, users=users)

@app.route('/update_user_role', methods=['POST'])
def update_user_role():
    username = request.form.get('username')
    new_role = request.form.get('new_role')

    # Make sure to check the input validity if needed
    if not username or not new_role:
        return jsonify({"error": "Invalid input"}), 400

    try:
        if db.update_user_role(username, new_role):  # Assuming this updates the DB and returns True on success
            return jsonify({"success": True, "message": "User role updated successfully."})
        else:
            return jsonify({"success": False, "message": "Failed to update user role"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": "An error occurred: " + str(e)}), 500

# knowledge repository
@app.route("/knowledge-repository", defaults={'article_id': None})
@app.route("/knowledge-repository/<int:article_id>")
def knowledge_repository(article_id):
    username = session.get("username")
    if username is None:
        return redirect(url_for('login'))  # Redirect to login page
    articles = db.get_all_articles()
    selected_article = db.get_article(article_id) if article_id else None
    user = db.get_user(username)
    #Convert enum to string here
    user_role = user.role.name if hasattr(user.role, 'name') else str(user.role)

    # Fetch comments for the selected article
    if selected_article:
        comments = db.get_comments(selected_article.id)
    else:
        comments = []
    if selected_article != None:
        author_role = db.get_user_role(selected_article.author_id)
    else:
        author_role = "student"
    return render_template('knowledge_repository.jinja', username=username, articles=articles, selected_article=selected_article, author_role=author_role, user_role=user_role, comments=comments)


@app.route("/add-article", methods=["POST"])
def add_article():
    title = request.form.get('title')
    content = request.form.get('content')
    author_id = session.get('username')  # Assuming username identifies the user

    success, message = db.insert_article(title, content, author_id)
    flash(message)
    return redirect(url_for('knowledge_repository'))

@app.route('/delete-article/<int:article_id>', methods=['DELETE'])
def delete_article(article_id):
    try:
        success = db.delete_article(article_id)
        if success:
            return jsonify({'message': 'Article deleted successfully'}), 200
        else:
            return jsonify({'error': 'Article not found or could not be deleted'}), 404
    except Exception as e:
        return jsonify({'error': 'An error occurred', 'details': str(e)}), 500

@app.route("/add-comment/<int:article_id>", methods=["POST"])
def add_comment(article_id):
    content = request.form.get('content')
    author_id = session.get('username')
    db.insert_comment(content, article_id, author_id)  # Insert the comment
    return redirect(url_for('knowledge_repository', article_id=article_id))

@app.route("/delete-comment/<int:comment_id>", methods=["POST"])
def delete_comment(comment_id):
    username = session.get("username")
    if not username:
        return jsonify({'error': 'You must be logged in to perform this action'}), 403

    user = db.get_user(username)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.role.name in ['ADMIN', 'ACADEMIC', 'ADMINISTRATIVE']:  # Ensure role is checked correctly
        success, message = db.delete_comment_db(comment_id)  # Assumed correct db function call
        if success:
            return jsonify({'message': message}), 200
        else:
            return jsonify({'error': message}), 404
    else:
        return jsonify({'error': 'You do not have permission to delete comments'}), 403


@app.route("/article/<int:article_id>")
def article_detail(article_id):
    article = db.get_article(article_id)  # Assuming this function fetches the article from the database
    comments = db.get_comments(article_id)  # Assuming this function fetches related comments
    return render_template('article_detail.jinja', article=article, comments=comments)

@app.route("/edit-article/<int:article_id>", methods=["GET", "POST"])
def edit_article(article_id):
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        db.update_article(article_id, title, content)  # Update the article in the database
        return redirect(url_for('articles'))
    article = db.get_article(article_id)  # Retrieve the article to edit
    return render_template("knowledge_repository.jinja", article=article)

@app.route("/save-article/<int:article_id>", methods=['POST'])
def save_article(article_id):
    # Ensure the request is in JSON format
    if not request.is_json:
        return jsonify({'message': 'Missing JSON in request'}), 400
    
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')

    # Now use the function from db.py
    success, message = db.update_article(article_id, title, content)
    if not success:
        if message == "Article not found":
            return jsonify({'message': message}), 404
        return jsonify({'message': message}), 400

    return jsonify({'message': 'Article updated successfully'}), 200


if __name__ == '__main__':
    # socketio.run(app)
    # for HTTPS Communication
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain('cert/info2222.test.crt', 'cert/info2222.test.key')
    with app.app_context():
        create_default_admin()
    app.run(debug=False, ssl_context=context, host='127.0.0.1', port=5000) # debug should be false after fully implemented