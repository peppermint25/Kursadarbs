# This was code for a project I did for the university comparing LLMs for coding

# Image upload website

This is a project for an image upload website. The backend is made with Python and Flask. This uses a MongoDB backend

## You will need Docker to launch this project ##

## Features

- User registration and login
- Profile management (update bio, profile picture)
- Post creation with image upload
- Commenting on posts
- Liking posts
- Following and unfollowing users
- Admin panel for managing users and posts
- Search functionality for users and posts

## Technologies Used

- **Frontend**: Angular, Angular Material
- **Backend**: Flask, Flask-PyMongo, Flask-JWT-Extended
- **Database**: MongoDB
- **Authentication**: JWT (JSON Web Tokens)
- **Image Processing**: PIL (Python Imaging Library)
- **Styling**: SCSS

## Installation

### Prerequisites

- Node.js and npm
- Python 3.x
- MongoDB

### Backend Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/peppermint25/Kursadarbs.git
   ```

2. Then you will need to launch the Docker for the Flask backend and MongoDB to work
   ```bash
     docker-compose up --build
   ```

### Frontend Setup

1. Navigate to the frontend or your choosing directory:
   ```bash
   cd /GH-4o
   cd /GH-Claude
   cd /ChatGPT-Projects
   cd /Claude-Projects-3.5
   cd /Claude-Free
   cd /GPT-4o
   ```

2. Install the required packages:
   ```bash
   npm install
   ```

3. Run the frontend server:
   ```bash
   ng serve
   ```

4. Open your browser and navigate to `http://localhost:4200`.

## API Endpoints

### Authentication

- **POST /register**: Register a new user
- **POST /login**: Login a user and return a JWT

### User Management

- **GET /profile/<user_id>**: Get user profile details
- **PUT /profile/update**: Update user profile (bio, profile picture)
- **POST /change_password**: Change user password
- **POST /follow/<user_id>**: Follow a user
- **POST /unfollow/<user_id>**: Unfollow a user

### Post Management

- **POST /upload**: Upload a new post with an image
- **GET /feed/all**: Get all posts
- **GET /feed/following**: Get posts from followed users
- **GET /post/<post_id>**: Get post details
- **DELETE /post/<post_id>**: Delete a post
- **POST /post/<post_id>/comment**: Add a comment to a post
- **DELETE /post/<post_id>/comment/<comment_timestamp>**: Delete a comment from a post
- **POST /react/<post_id>**: Add or change a reaction to a post

### Admin Management

- **GET /admin/panel**: Get all users and posts (admin only)
- **GET /admin/user/<user_id>**: View user activity logs and posts (admin only)
- **POST /admin/promote/<user_id>**: Promote a user to admin (admin only)
- **POST /admin/demote/<user_id>**: Demote a user from admin (admin only)
- **DELETE /admin/delete_user/<user_id>**: Delete a user and their posts (admin only)
- **DELETE /admin/delete_post/<post_id>**: Delete a post (admin only)
- **GET /admin/check**: Check admin status (admin only)

### Search

- **GET /search**: Search for users and posts

### Static Files

- **GET /uploads/<path:filename>**: Serve uploaded files (requires JWT)
- **GET /uploads/profile_pictures/<path:filename>**: Serve profile pictures (requires JWT)
- **GET /images/<path:filename>**: Serve image files (requires JWT)
- **GET /api/images/default_avatar**: Serve default avatar (requires JWT)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
