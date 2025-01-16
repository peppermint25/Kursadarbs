from flask import Flask
from flask_pymongo import PyMongo
import bcrypt
import os

# Initialize Flask app
app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://localhost:27017/mydatabase"  # Use service name 'db' for Docker

# Initialize MongoDB
mongo = PyMongo(app)

def create_admin_user():
    username = "admin"
    email = "admin@example.com"
    password = "Admin1234"
    role = "admin"

    if mongo.db.users.find_one({'username': username}) or mongo.db.users.find_one({'email': email}):
        print("Admin user already exists.")
        return

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())  # Hash the password

    mongo.db.users.insert_one({
        'username': username,
        'email': email,  # Store the email
        'password': hashed_password,  # Store the hashed password
        'followers': [],
        'following': [],
        'profile_bio': "Admin user",
        'profile_picture': None,
        'role': role  # Set the role to admin
    })
    print("Admin user created successfully.")

if __name__ == "__main__":
    with app.app_context():
        create_admin_user()
