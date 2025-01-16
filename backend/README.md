# Instagram Clone API

## Endpoints

### GET /

**Description**: Welcome message.

**Response**:
- 200: `{ "message": "Welcome to the Instagram clone API!" }`

### POST /register

**Description**: Register a new user.

**Request Body**:
- `username`: string (required)
- `email`: string (required)
- `password`: string (required)
- `profile_bio`: string (optional)

**Response**:
- 201: `{ "message": "User registered successfully" }`
- 400: `{ "message": "Error message" }`

### POST /login

**Description**: Login a user.

**Request Body**:
- `username`: string (optional)
- `email`: string (optional)
- `password`: string (required)

**Response**:
- 200: `{ "access_token": "token" }`
- 401: `{ "message": "Invalid credentials" }`

### POST /change_password

**Description**: Change user password.

**Request Headers**:
- `Authorization`: Bearer token

**Request Body**:
- `current_password`: string (required)
- `new_password`: string (required)

**Response**:
- 200: `{ "message": "Password changed successfully" }`
- 401: `{ "message": "Current password is incorrect" }`
- 400: `{ "message": "Password must be at least 8 characters long and contain both letters and numbers" }`

### POST /upload

**Description**: Upload an image.

**Request Headers**:
- `Authorization`: Bearer token

**Request Body**:
- `file`: file (required)
- `caption`: string (optional)
- `tags`: string (optional, comma-separated)

**Response**:
- 201: `{ "message": "File uploaded successfully", "image_url": "url" }`
- 400: `{ "message": "Error message" }`

### GET /feed/all

**Description**: Get all posts.

**Response**:
- 200: `[{ "post_id": "id", "user_id": "id", "username": "username", "profile_picture": "url", "image_url": "url", "caption": "caption", "tags": ["tag"], "reactions": {}, "comments": 0, "timestamp": "timestamp" }]`
- 500: `{ "message": "Error message" }`

### GET /feed/following

**Description**: Get posts from followed users.

**Request Headers**:
- `Authorization`: Bearer token

**Response**:
- 200: `[{ "post_id": "id", "user_id": "id", "username": "username", "profile_picture": "url", "image_url": "url", "caption": "caption", "tags": ["tag"], "reactions": {}, "comments": 0, "timestamp": "timestamp" }]`
- 500: `{ "message": "Error message" }`

### POST /react/<post_id>

**Description**: Add or change reaction to a post.

**Request Headers**:
- `Authorization`: Bearer token

**Request Body**:
- `reaction`: string (required)

**Response**:
- 200: `{ "message": "Reaction updated successfully", "reactions": {} }`
- 400: `{ "message": "Reaction type is required" }`
- 404: `{ "message": "Post not found" }`

### POST /post/{post_id}/comment

**Description**: Add a comment to a post.

**Request Headers**:
- `Authorization`: Bearer token

**Request Body**:
- `text`: string (required)

**Response**:
- 201: `{ "message": "Comment added successfully", "comment": {} }`
- 400: `{ "message": "Comment text is required" }`
- 500: `{ "message": "Error adding comment" }`

### DELETE /post/{post_id}/comment/{comment_timestamp}

**Description**: Delete a comment from a post. Only the comment author or an admin can delete comments.

**Request Headers**:
- `Authorization`: Bearer token

**Response**:
- 200: `{ "message": "Comment deleted successfully" }`
- 404: `{ "message": "Comment not found or unauthorized" }`
- 500: `{ "message": "Error deleting comment" }`

### PUT /profile/update

**Description**: Update user profile.

**Request Headers**:
- `Authorization`: Bearer token

**Request Body**:
- `profile_bio`: string (optional)
- `profile_picture`: file (optional)

**Response**:
- 200: `{ "message": "Profile updated successfully" }`
- 400: `{ "message": "No valid data provided to update" }`

### GET /admin/panel

**Description**: Get all users and posts (Admin only).

**Request Headers**:
- `Authorization`: Bearer token

**Response**:
- 200: `{ "users": [{ "_id": "id", "username": "username", "followers": 0, "following": 0 }], "posts": [{ "_id": "id", "user_id": "id", "caption": "caption" }] }`
- 403: `{ "message": "Unauthorized access" }`

### GET /admin/check

**Description**: Check if the current user has admin privileges.

**Request Headers**:
- `Authorization`: Bearer token

**Response**:
- 200: `{ "isAdmin": boolean }`
- 404: `{ "message": "User not found" }`
- 500: `{ "message": "Error checking admin status" }`

### DELETE /admin/delete_user/<user_id>

**Description**: Delete any user (Admin only).

**Request Headers**:
- `Authorization`: Bearer token

**Response**:
- 200: `{ "message": "User and their posts deleted successfully" }`
- 403: `{ "message": "Unauthorized access" }`

### DELETE /admin/delete_post/<post_id>

**Description**: Delete any post (Admin only).

**Request Headers**:
- `Authorization`: Bearer token

**Response**:
- 200: `{ "message": "Post deleted successfully" }`
- 403: `{ "message": "Unauthorized access" }`
