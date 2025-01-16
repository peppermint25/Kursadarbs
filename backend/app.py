from flask import Flask, request, jsonify, send_from_directory
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
import bcrypt  # Import bcrypt
from bson.objectid import ObjectId
import os
import datetime
import re  # Import regex for email validation
import logging  # Import logging
from flask_cors import CORS  # Import CORS
from PIL import Image  # Import PIL for image processing

# Initialize Flask app
app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv("MONGO_URI", "mongodb://db:27017/mydatabase")  # Use environment variable
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "your-secret-key")  # Use environment variable

# Initialize MongoDB and JWTManager
mongo = PyMongo(app)
jwt = JWTManager(app)

# Initialize logging
logging.basicConfig(level=logging.INFO)

# Enable CORS
CORS(app)

# Ensure unique indexes for username and email
mongo.db.users.create_index("username", unique=True)
mongo.db.users.create_index("email", unique=True)

# Allowed extensions for file uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

IMAGES_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'images')
if not os.path.exists(IMAGES_FOLDER):
    os.makedirs(IMAGES_FOLDER)

app.config['IMAGES_FOLDER'] = IMAGES_FOLDER

PROFILE_PICTURES_FOLDER = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pictures')
if not os.path.exists(PROFILE_PICTURES_FOLDER):
    os.makedirs(PROFILE_PICTURES_FOLDER)

# Set maximum file size (e.g., 5MB)
MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_PROFILE_PICTURE_SIZE = (300, 300)  # Maximum dimensions for profile pictures

# Helper function to check if file type is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper function to validate email format
def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

# Helper function to check password strength
def is_strong_password(password):
    return len(password) >= 8 and re.search(r"[A-Za-z]", password) and re.search(r"[0-9]", password)

# Helper function to log user activities with additional data
def log_activity(user_id, action, data=None):
    log_entry = {
        'user_id': user_id,
        'action': action,
        'timestamp': datetime.datetime.utcnow()
    }
    if data:
        log_entry['data'] = data
    mongo.db.activity_logs.insert_one(log_entry)

# Helper function to send notifications
def send_notification(user_id, message):
    mongo.db.notifications.insert_one({
        'user_id': user_id,
        'message': message,
        'timestamp': datetime.datetime.utcnow(),
        'read': False
    })

# Helper function to downscale image
def downscale_image(image_path, max_size):
    with Image.open(image_path) as img:
        img.thumbnail(max_size, Image.LANCZOS)  # Use Image.LANCZOS instead of Image.ANTIALIAS
        img.save(image_path)

# Custom error handler for 404 Not Found
@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Resource not found'}), 404

# Custom error handler for 500 Internal Server Error
@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'message': 'Internal server error'}), 500

@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'Welcome to the Instagram clone API!'})

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    try:
        users = mongo.db.users.find()
        response = [
            {
                'username': user['username'],
                'followers': len(user['followers']),
                'following': len(user['following'])
            }
            for user in users
        ]
        return jsonify(response), 200
    except Exception as e:
        logging.error(f"Error fetching users: {str(e)}")
        return jsonify({'message': 'Error fetching users'}), 500

# User registration endpoint
@app.route('/register', methods=['POST'])
def register():
    try:
        username = request.json.get('username')
        email = request.json.get('email')  # Add email field
        password = request.json.get('password')
        profile_bio = request.json.get('profile_bio', "")

        if not username or not email or not password:
            return jsonify({'message': 'Missing username, email, or password'}), 400

        if not is_valid_email(email):
            return jsonify({'message': 'Invalid email format'}), 400

        if not is_strong_password(password):
            return jsonify({'message': 'Password must be at least 8 characters long and contain both letters and numbers'}), 400

        if mongo.db.users.find_one({'username': username}) or mongo.db.users.find_one({'email': email}):
            return jsonify({'message': 'User already exists'}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())  # Hash the password

        user_id = mongo.db.users.insert_one({
            'username': username,
            'email': email,  # Store the email
            'password': hashed_password,  # Store the hashed password
            'followers': [],
            'following': [],
            'profile_bio': profile_bio,
            'profile_picture': None,
            'role': 'user'  # Default role to user
        }).inserted_id

        log_activity(user_id, 'register')  # Log registration activity
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        logging.error(f"Error registering user: {str(e)}")
        return jsonify({'message': 'Error registering user'}), 500

# User login endpoint
@app.route('/login', methods=['POST'])
def login():
    try:
        username = request.json.get('username')
        email = request.json.get('email')  # Add email field
        password = request.json.get('password')
        user = mongo.db.users.find_one({'$or': [{'username': username}, {'email': email}]})  # Find by username or email

        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):  # Verify the hashed password
            return jsonify({'message': 'Invalid credentials'}), 401

        access_token = create_access_token(identity=str(user['_id']))
        log_activity(user['_id'], 'login')  # Log login activity
        return jsonify(access_token=access_token, username=user['username']), 200
    except Exception as e:
        logging.error(f"Error logging in user: {str(e)}")
        return jsonify({'message': 'Error logging in user'}), 500

# Change password endpoint
@app.route('/change_password', methods=['POST'])
@jwt_required()
def change_password():
    try:
        current_user_id = get_jwt_identity()
        current_password = request.json.get('current_password')
        new_password = request.json.get('new_password')

        user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})

        if not user or not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
            return jsonify({'message': 'Current password is incorrect'}), 401

        if not is_strong_password(new_password):
            return jsonify({'message': 'Password must be at least 8 characters long and contain both letters and numbers'}), 400

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        mongo.db.users.update_one({'_id': ObjectId(current_user_id)}, {'$set': {'password': hashed_password}})
        log_activity(current_user_id, 'change_password')  # Log password change activity
        return jsonify({'message': 'Password changed successfully'}), 200
    except Exception as e:
        logging.error(f"Error changing password: {str(e)}")
        return jsonify({'message': 'Error changing password'}), 500

# Image upload endpoint
@app.route('/upload', methods=['POST'])
@jwt_required()
def upload():
    try:
        current_user = get_jwt_identity()

        if 'file' not in request.files:
            return jsonify({'message': 'No file part'}), 400

        file = request.files['file']
        caption = request.form.get('caption', "")
        tags = request.form.get('tags', "").split(',')

        if file.filename == '':
            return jsonify({'message': 'No selected file'}), 400

        if file and allowed_file(file.filename):
            if file.content_length > MAX_FILE_SIZE:
                return jsonify({'message': 'File size exceeds the maximum limit of 5MB'}), 400

            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            image_url = f'/uploads/{filename}'
            post = {
                'user_id': current_user,
                'image_url': image_url,
                'caption': caption,
                'tags': [tag.strip() for tag in tags if tag.strip()],
                'timestamp': datetime.datetime.utcnow(),
                'reactions': {},  # Reactions are stored as a dictionary {'user_id': 'reaction_type'}
                'comments': []
            }
            post_id = mongo.db.posts.insert_one(post).inserted_id
            log_activity(current_user, 'upload_post', {'post_id': str(post_id), 'image_url': image_url, 'caption': caption})
            return jsonify({'message': 'File uploaded successfully', 'image_url': image_url, 'post_id': str(post_id)}), 201

        return jsonify({'message': 'Invalid file type'}), 400
    except Exception as e:
        logging.error(f"Error uploading file: {str(e)}")
        return jsonify({'message': 'Error uploading file'}), 500

# Serve static files from uploads and images directories
@app.route('/uploads/<path:filename>')
# @jwt_required()
def serve_upload_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/uploads/profile_pictures/<path:filename>')
# @jwt_required()
def serve_profile_picture(filename):
    return send_from_directory(PROFILE_PICTURES_FOLDER, filename)

@app.route('/images/<path:filename>')
# @jwt_required()
def serve_image_file(filename):
    return send_from_directory(app.config['IMAGES_FOLDER'], filename)

# Serve default avatar
@app.route('/api/images/default_avatar')
# @jwt_required()
def serve_default_avatar():
    return send_from_directory(app.config['IMAGES_FOLDER'], 'default-avatar.png')

# Feed for all posts
@app.route('/feed/all', methods=['GET'])
@jwt_required()
def feed_all():
    try:
        posts = mongo.db.posts.find().sort('timestamp', -1)
        response = [
            {
                'post_id': str(post['_id']),
                'user_id': post['user_id'],
                'username': mongo.db.users.find_one({'_id': ObjectId(post['user_id'])})['username'],
                'profile_picture': mongo.db.users.find_one({'_id': ObjectId(post['user_id'])}).get('profile_picture', None),
                'image_url': post['image_url'],
                'caption': post.get('caption', ""),
                'tags': post.get('tags', []),
                'reactions': post.get('reactions', {}),
                'comments': post.get('comments', []),  # Include full comments
                'timestamp': post.get('timestamp', "")
            }
            for post in posts
        ]
        return jsonify(response), 200
    except Exception as e:
        logging.error(f"Error fetching all posts feed: {str(e)}")
        return jsonify({'message': 'Error fetching all posts feed'}), 500

# Feed for followed users' posts
@app.route('/feed/following', methods=['GET'])
@jwt_required()
def feed_following():
    try:
        current_user_id = get_jwt_identity()
        user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
        following = user.get('following', [])
        following.append(current_user_id)  # Include the current user's ID

        posts = mongo.db.posts.find({'user_id': {'$in': following}}).sort('timestamp', -1)
        response = [
            {
                'post_id': str(post['_id']),
                'user_id': post['user_id'],
                'username': mongo.db.users.find_one({'_id': ObjectId(post['user_id'])})['username'],
                'profile_picture': mongo.db.users.find_one({'_id': ObjectId(post['user_id'])}).get('profile_picture', None),
                'image_url': post['image_url'],
                'caption': post.get('caption', ""),
                'tags': post.get('tags', []),
                'reactions': post.get('reactions', {}),
                'comments': post.get('comments', []),
                'timestamp': post.get('timestamp', "")
            }
            for post in posts
        ]
        return jsonify(response), 200
    except Exception as e:
        logging.error(f"Error fetching following feed: {str(e)}")
        return jsonify({'message': 'Error fetching following feed'}), 500

# Add comment endpoint
@app.route('/post/<post_id>/comment', methods=['POST'])
@jwt_required()
def add_comment(post_id):
    try:
        current_user_id = get_jwt_identity()
        comment_text = request.json.get('text')

        if not comment_text:
            return jsonify({'message': 'Comment text is required'}), 400

        user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
        comment = {
            'user_id': current_user_id,
            'username': user['username'],
            'text': comment_text,
            'timestamp': datetime.datetime.utcnow()
        }

        mongo.db.posts.update_one(
            {'_id': ObjectId(post_id)},
            {'$push': {'comments': comment}}
        )

        log_activity(current_user_id, f'comment_post_{post_id}', {'comment': comment_text})
        return jsonify({'message': 'Comment added successfully', 'comment': comment}), 201
    except Exception as e:
        logging.error(f"Error adding comment: {str(e)}")
        return jsonify({'message': 'Error adding comment'}), 500

# Delete comment endpoint
@app.route('/post/<post_id>/comment/<comment_timestamp>', methods=['DELETE'])
@jwt_required()
def delete_comment(post_id, comment_timestamp):
    try:
        current_user_id = get_jwt_identity()
        user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
        post = mongo.db.posts.find_one({'_id': ObjectId(post_id)})

        if not post:
            return jsonify({'message': 'Post not found'}), 404

        # Convert timestamp string to datetime
        comment_time = datetime.datetime.fromisoformat(comment_timestamp.replace('Z', '+00:00'))

        # Allow deletion by comment author, post author, or admin
        can_delete = (
            user.get('role') == 'admin' or  # Is admin
            current_user_id == post['user_id'] or  # Is post author
            any(  # Is comment author
                comment['user_id'] == current_user_id and comment['timestamp'] == comment_time
                for comment in post.get('comments', [])
            )
        )

        if not can_delete:
            return jsonify({'message': 'Unauthorized to delete this comment'}), 403

        update_result = mongo.db.posts.update_one(
            {'_id': ObjectId(post_id)},
            {'$pull': {'comments': {'timestamp': comment_time}}}
        )

        if update_result.modified_count == 0:
            return jsonify({'message': 'Comment not found'}), 404

        log_activity(current_user_id, f'delete_comment_{post_id}')
        return jsonify({'message': 'Comment deleted successfully'}), 200
    except Exception as e:
        logging.error(f"Error deleting comment: {str(e)}")
        return jsonify({'message': 'Error deleting comment'}), 500

# Add or change reaction endpoint
@app.route('/react/<post_id>', methods=['POST'])
@jwt_required()
def react_post(post_id):
    try:
        current_user_id = get_jwt_identity()
        reaction_type = request.json.get('reaction')

        if not reaction_type:
            return jsonify({'message': 'Reaction type is required'}), 400

        post = mongo.db.posts.find_one({'_id': ObjectId(post_id)})

        if not post:
            return jsonify({'message': 'Post not found'}), 404

        reactions = post.get('reactions', {})

        # Update reaction
        if reactions.get(current_user_id) == reaction_type:
            del reactions[current_user_id]  # Remove reaction if it's the same
        else:
            reactions[current_user_id] = reaction_type

        # Update in database
        mongo.db.posts.update_one({'_id': ObjectId(post_id)}, {'$set': {'reactions': reactions}})

        # Return updated post reactions
        updated_post = mongo.db.posts.find_one({'_id': ObjectId(post_id)})
        return jsonify({
            'message': 'Reaction updated successfully',
            'reactions': updated_post.get('reactions', {})
        }), 200
    except Exception as e:
        logging.error(f"Error updating reaction: {str(e)}")
        return jsonify({'message': 'Error updating reaction'}), 500

# Update user profile
@app.route('/profile/update', methods=['PUT'])
@jwt_required()
def update_profile():
    try:
        current_user_id = get_jwt_identity()
        profile_bio = request.form.get('profile_bio', None)  # Use request.form to get form data
        profile_picture = request.files.get('profile_picture', None)

        update_data = {}
        if profile_bio is not None:
            update_data['profile_bio'] = profile_bio

        if profile_picture and allowed_file(profile_picture.filename):
            if profile_picture.content_length > MAX_FILE_SIZE:
                return jsonify({'message': 'Profile picture size exceeds the maximum limit of 5MB'}), 400

            filename = secure_filename(profile_picture.filename)
            filepath = os.path.join(PROFILE_PICTURES_FOLDER, filename)
            profile_picture.save(filepath)

            # Downscale the image if it exceeds the maximum dimensions
            downscale_image(filepath, MAX_PROFILE_PICTURE_SIZE)

            update_data['profile_picture'] = f'/uploads/profile_pictures/{filename}'

        if update_data:
            mongo.db.users.update_one({'_id': ObjectId(current_user_id)}, {'$set': update_data})
            log_activity(current_user_id, 'update_profile', update_data)  # Log profile update activity with update data
            return jsonify({'message': 'Profile updated successfully'}), 200

        return jsonify({'message': 'No valid data provided to update'}), 400
    except Exception as e:
        logging.error(f"Error updating profile: {str(e)}")
        logging.exception("Exception occurred")
        return jsonify({'message': 'Error updating profile'}), 500

# Follow user endpoint
@app.route('/follow/<user_id>', methods=['POST'])
@jwt_required()
def follow_user(user_id):
    try:
        current_user_id = get_jwt_identity()
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})

        if not user:
            return jsonify({'message': 'User not found'}), 404

        mongo.db.users.update_one({'_id': ObjectId(current_user_id)}, {'$addToSet': {'following': user_id}})
        mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$addToSet': {'followers': current_user_id}})
        log_activity(current_user_id, f'follow_user_{user_id}', {'followed_user_id': user_id})  # Log follow activity
        send_notification(user_id, f"{mongo.db.users.find_one({'_id': ObjectId(current_user_id)})['username']} started following you")
        return jsonify({'message': 'User followed successfully'}), 200
    except Exception as e:
        logging.error(f"Error following user: {str(e)}")
        return jsonify({'message': 'Error following user'}), 500

# Unfollow user endpoint
@app.route('/unfollow/<user_id>', methods=['POST'])
@jwt_required()
def unfollow_user(user_id):
    try:
        current_user_id = get_jwt_identity()
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})

        if not user:
            return jsonify({'message': 'User not found'}), 404

        mongo.db.users.update_one({'_id': ObjectId(current_user_id)}, {'$pull': {'following': user_id}})
        mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$pull': {'followers': current_user_id}})
        log_activity(current_user_id, f'unfollow_user_{user_id}')  # Log unfollow activity
        return jsonify({'message': 'User unfollowed successfully'}), 200
    except Exception as e:
        logging.error(f"Error unfollowing user: {str(e)}")
        return jsonify({'message': 'Error unfollowing user'}), 500

# Admin panel: Get all users and posts
@app.route('/admin/panel', methods=['GET'])
@jwt_required()
def admin_panel():
    try:
        current_user_id = get_jwt_identity()
        admin_user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})

        if not admin_user or admin_user.get('role') != 'admin':
            return jsonify({'message': 'Unauthorized access'}), 403

        users = list(mongo.db.users.find({}, {'password': 0}))
        posts = list(mongo.db.posts.find())

        return jsonify({
            'users': [{'_id': str(user['_id']), 'username': user['username'], 'followers': len(user['followers']), 'following': len(user['following']), 'role': user.get('role', 'user')} for user in users],
            'posts': [{'_id': str(post['_id']), 'user_id': post['user_id'], 'caption': post['caption'], 'image_url': post['image_url']} for post in posts]
        }), 200
    except Exception as e:
        logging.error(f"Error fetching admin panel data: {str(e)}")
        return jsonify({'message': 'Error fetching admin panel data'}), 500

# Admin: View user activity logs and posts
@app.route('/admin/user/<user_id>', methods=['GET'])
@jwt_required()
def view_user_details(user_id):
    try:
        admin_user_id = get_jwt_identity()
        admin_user = mongo.db.users.find_one({'_id': ObjectId(admin_user_id)})

        if not admin_user or admin_user.get('role') != 'admin':
            return jsonify({'message': 'Unauthorized access'}), 403

        user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0})
        logs = list(mongo.db.activity_logs.find({'user_id': user_id}).sort('timestamp', -1))
        posts = list(mongo.db.posts.find({'user_id': user_id}).sort('timestamp', -1))

        return jsonify({
            'user': {
                '_id': str(user['_id']),
                'username': user['username'],
                'followers': len(user['followers']),
                'following': len(user['following']),
                'profile_bio': user.get('profile_bio', ""),
                'profile_picture': user.get('profile_picture', None)
            },
            'logs': [{'_id': str(log['_id']), 'action': log['action'], 'timestamp': log['timestamp']} for log in logs],
            'posts': [{'_id': str(post['_id']), 'image_url': post['image_url'], 'caption': post['caption'], 'tags': post['tags'], 'timestamp': post['timestamp']} for post in posts]
        }), 200
    except Exception as e:
        logging.error(f"Error fetching user details: {str(e)}")
        return jsonify({'message': 'Error fetching user details'}), 500

# Admin: Promote user to admin
@app.route('/admin/promote/<user_id>', methods=['POST'])
@jwt_required()
def promote_user(user_id):
    try:
        current_user_id = get_jwt_identity()  # Define current_user_id
        mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'role': 'admin'}})
        log_activity(current_user_id, f'promote_user_{user_id}')  # Log promotion activity
        return jsonify({'message': 'User promoted to admin successfully'}), 200
    except Exception as e:
        logging.error(f"Error promoting user: {str(e)}")
        return jsonify({'message': 'Error promoting user'}), 500

# Admin: Demote user from admin
@app.route('/admin/demote/<user_id>', methods=['POST'])
@jwt_required()
def demote_user(user_id):
    try:
        current_user_id = get_jwt_identity()
        admin_user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})

        if not admin_user or admin_user.get('role') != 'admin':
            return jsonify({'message': 'Unauthorized access'}), 403

        mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'role': 'user'}})
        log_activity(current_user_id, f'demote_user_{user_id}')  # Log demotion activity
        return jsonify({'message': 'User demoted from admin successfully'}), 200
    except Exception as e:
        logging.error(f"Error demoting user: {str(e)}")
        return jsonify({'message': 'Error demoting user'}), 500

# Admin: Delete any user
@app.route('/admin/delete_user/<user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    try:
        current_user_id = get_jwt_identity()
        admin_user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})

        if not admin_user or admin_user.get('role') != 'admin':
            return jsonify({'message': 'Unauthorized access'}), 403

        mongo.db.users.delete_one({'_id': ObjectId(user_id)})
        mongo.db.posts.delete_many({'user_id': user_id})
        log_activity(current_user_id, f'delete_user_{user_id}')  # Log user deletion activity
        return jsonify({'message': 'User and their posts deleted successfully'}), 200
    except Exception as e:
        logging.error(f"Error deleting user: {str(e)}")
        return jsonify({'message': 'Error deleting user'}), 500

# Admin: Delete any post
@app.route('/admin/delete_post/<post_id>', methods=['DELETE'])
@jwt_required()
def delete_post(post_id):
    try:
        current_user_id = get_jwt_identity()
        admin_user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})

        if not admin_user or admin_user.get('role') != 'admin':
            return jsonify({'message': 'Unauthorized access'}), 403

        mongo.db.posts.delete_one({'_id': ObjectId(post_id)})
        log_activity(current_user_id, f'delete_post_{post_id}')  # Log post deletion activity
        return jsonify({'message': 'Post deleted successfully'}), 200
    except Exception as e:
        logging.error(f"Error deleting post: {str(e)}")
        return jsonify({'message': 'Error deleting post'}), 500

# Admin: Check admin status
@app.route('/admin/check', methods=['GET'])
@jwt_required()
def check_admin():
    try:
        print("Checking admin status")
        current_user_id = get_jwt_identity()
        print(f"Current user ID: {current_user_id}")
        user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    
        if not user:
            return jsonify({'message': 'User not found'}), 404

        is_admin = user.get('role') == 'admin'
        return jsonify({'isAdmin': is_admin}), 200
    except Exception as e:
        logging.error(f"Error checking admin status: {str(e)}")
        return jsonify({'message': 'Error checking admin status'}), 500

# Combined view profile endpoint
@app.route('/profile', methods=['GET'])
@app.route('/profile/<user_id>', methods=['GET'])
@jwt_required(optional=True)
def view_profile(user_id=None):
    try:
        current_user_id = get_jwt_identity()
        if user_id is None:
            user_id = current_user_id

        user = mongo.db.users.find_one({'_id': ObjectId(user_id)}, {'password': 0})

        if not user:
            return jsonify({'message': 'User not found'}), 404

        is_current_user = str(user['_id']) == current_user_id
        is_following = False
        is_followed_by = False

        if current_user_id and not is_current_user:
            current_user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
            is_following = user_id in current_user.get('following', [])
            is_followed_by = current_user_id in user.get('followers', [])

        posts = list(mongo.db.posts.find({'user_id': user_id}, {'image_url': 1, '_id': 1}))

        profile_data = {
            'user_id': str(user['_id']),  # Include user_id in the response
            'username': user['username'],
            'followers': len(user['followers']),
            'following': len(user['following']),
            'profile_bio': user.get('profile_bio', ""),
            'profile_picture': user.get('profile_picture', None),
            'is_current_user': is_current_user,
            'is_following': is_following,
            'is_followed_by': is_followed_by,
            'posts': [{'post_id': str(post['_id']), 'image_url': post['image_url']} for post in posts]
        }

        return jsonify(profile_data), 200
    except Exception as e:
        logging.error(f"Error viewing profile: {str(e)}")
        return jsonify({'message': 'Error viewing profile'}), 500
    
# Search endpoint
@app.route('/search', methods=['GET'])
@jwt_required()
def search():
    try:
        query = request.args.get('q', '').strip()
        search_type = request.args.get('type', 'all')  # 'all', 'users', 'tags'

        if not query:
            return jsonify({'users': [], 'posts': []}), 200

        results = {'users': [], 'posts': []}

        if search_type in ['all', 'users']:
            # Search users by username
            users = mongo.db.users.find({
                'username': {'$regex': query, '$options': 'i'}
            }, {'password': 0}).limit(10)
            results['users'] = [{
                '_id': str(user['_id']),
                'username': user['username'],
                'profile_picture': user.get('profile_picture'),
                'followers': len(user['followers']),
                'following': len(user['following'])
            } for user in users]

        if search_type in ['all', 'tags']:
            # Search posts by tags or caption
            posts = mongo.db.posts.find({
                '$or': [
                    {'tags': {'$regex': query, '$options': 'i'}},
                    {'caption': {'$regex': query, '$options': 'i'}}
                ]
            }).limit(20)
            results['posts'] = [{
                '_id': str(post['_id']),
                'user_id': post['user_id'],
                'username': mongo.db.users.find_one({'_id': ObjectId(post['user_id'])})['username'],
                'image_url': post['image_url'],
                'caption': post.get('caption', ''),
                'tags': post.get('tags', [])
            } for post in posts]

        return jsonify(results), 200
    except Exception as e:
        logging.error(f"Error performing search: {str(e)}")
        return jsonify({'message': 'Error performing search'}), 500

@app.route('/post/<post_id>', methods=['GET'])
@jwt_required()
def get_post_details(post_id):
    try:
        post = mongo.db.posts.find_one({'_id': ObjectId(post_id)})
        if not post:
            return jsonify({'message': 'Post not found'}), 404

        user = mongo.db.users.find_one({'_id': ObjectId(post['user_id'])})
        post_details = {
            'image_url': post['image_url'],
            'caption': post.get('caption', ""),
            'tags': post.get('tags', []),
            'reactions': post.get('reactions', {}),
            'comments': post.get('comments', []),
            'username': user['username'],  # Include username
            'profile_picture': user.get('profile_picture', None)  # Include profile picture
        }
        return jsonify(post_details), 200
    except Exception as e:
        logging.error(f"Error fetching post details: {str(e)}")
        return jsonify({'message': 'Error fetching post details'}), 500

@app.route('/post/<post_id>', methods=['DELETE'])
@jwt_required()
def remove_post(post_id):
    try:
        current_user_id = get_jwt_identity()
        post = mongo.db.posts.find_one({'_id': ObjectId(post_id)})

        if not post:
            return jsonify({'message': 'Post not found'}), 404

        if post['user_id'] != current_user_id:
            return jsonify({'message': 'Unauthorized to delete this post'}), 403

        mongo.db.posts.delete_one({'_id': ObjectId(post_id)})
        log_activity(current_user_id, 'delete_post', {'post_id': post_id, 'image_url': post['image_url'], 'caption': post['caption']})
        return jsonify({'message': 'Post deleted successfully'}), 200
    except Exception as e:
        logging.error(f"Error deleting post: {str(e)}")
        return jsonify({'message': 'Error deleting post'}), 500

if __name__ == "__main__":
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(host="0.0.0.0", port=5000)
