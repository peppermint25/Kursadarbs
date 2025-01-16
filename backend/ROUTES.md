# Backend API Documentation

This document provides details about the backend API routes, including their requirements and returned data.

## Authentication

### POST /register

**Description**: Register a new user.

**Request Body**:
```json
{
  "username": "string",
  "email": "string",
  "password": "string",
  "profile_bio": "string" (optional)
}
```

**Response**:
- 201 Created: `{"message": "User registered successfully"}`
- 400 Bad Request: `{"message": "Error message"}`
- 500 Internal Server Error: `{"message": "Error registering user"}`

### POST /login

**Description**: Login a user and return a JWT.

**Request Body**:
```json
{
  "username": "string",
  "email": "string",
  "password": "string"
}
```

**Response**:
- 200 OK: `{"access_token": "string", "username": "string"}`
- 401 Unauthorized: `{"message": "Invalid credentials"}`
- 500 Internal Server Error: `{"message": "Error logging in user"}`

### POST /change_password

**Description**: Change user password.

**Request Body**:
```json
{
  "current_password": "string",
  "new_password": "string"
}
```

**Response**:
- 200 OK: `{"message": "Password changed successfully"}`
- 401 Unauthorized: `{"message": "Current password is incorrect"}`
- 400 Bad Request: `{"message": "Password must be at least 8 characters long and contain both letters and numbers"}`
- 500 Internal Server Error: `{"message": "Error changing password"}`

## User Management

### GET /profile/<user_id>

**Description**: Get user profile details.

**Response**:
- 200 OK: 
```json
{
  "user_id": "string",
  "username": "string",
  "followers": "number",
  "following": "number",
  "profile_bio": "string",
  "profile_picture": "string | null",
  "is_current_user": "boolean",
  "is_following": "boolean",
  "is_followed_by": "boolean",
  "posts": [
    {
      "post_id": "string",
      "image_url": "string"
    }
  ]
}
```
- 404 Not Found: `{"message": "User not found"}`
- 500 Internal Server Error: `{"message": "Error viewing profile"}`

### PUT /profile/update

**Description**: Update user profile (bio, profile picture).

**Request Body**:
- `profile_bio`: string (optional)
- `profile_picture`: file (optional)

**Response**:
- 200 OK: `{"message": "Profile updated successfully"}`
- 400 Bad Request: `{"message": "No valid data provided to update"}`
- 500 Internal Server Error: `{"message": "Error updating profile"}`

### POST /follow/<user_id>

**Description**: Follow a user.

**Response**:
- 200 OK: `{"message": "User followed successfully"}`
- 404 Not Found: `{"message": "User not found"}`
- 500 Internal Server Error: `{"message": "Error following user"}`

### POST /unfollow/<user_id>

**Description**: Unfollow a user.

**Response**:
- 200 OK: `{"message": "User unfollowed successfully"}`
- 404 Not Found: `{"message": "User not found"}`
- 500 Internal Server Error: `{"message": "Error unfollowing user"}`

## Post Management

### POST /upload

**Description**: Upload a new post with an image.

**Request Body**:
- `file`: file
- `caption`: string (optional)
- `tags`: string (comma-separated, optional)

**Response**:
- 201 Created: `{"message": "File uploaded successfully", "image_url": "string", "post_id": "string"}`
- 400 Bad Request: `{"message": "Error message"}`
- 500 Internal Server Error: `{"message": "Error uploading file"}`

### GET /feed/all

**Description**: Get all posts.

**Response**:
- 200 OK: 
```json
[
  {
    "post_id": "string",
    "user_id": "string",
    "username": "string",
    "profile_picture": "string | null",
    "image_url": "string",
    "caption": "string",
    "tags": ["string"],
    "reactions": {"user_id": "reaction_type"},
    "comments": [
      {
        "user_id": "string",
        "username": "string",
        "text": "string",
        "timestamp": "string"
      }
    ],
    "timestamp": "string"
  }
]
```
- 500 Internal Server Error: `{"message": "Error fetching all posts feed"}`

### GET /feed/following

**Description**: Get posts from followed users.

**Response**:
- 200 OK: 
```json
[
  {
    "post_id": "string",
    "user_id": "string",
    "username": "string",
    "profile_picture": "string | null",
    "image_url": "string",
    "caption": "string",
    "tags": ["string"],
    "reactions": {"user_id": "reaction_type"},
    "comments": [
      {
        "user_id": "string",
        "username": "string",
        "text": "string",
        "timestamp": "string"
      }
    ],
    "timestamp": "string"
  }
]
```
- 500 Internal Server Error: `{"message": "Error fetching following feed"}`

### GET /post/<post_id>

**Description**: Get post details.

**Response**:
- 200 OK: 
```json
{
  "image_url": "string",
  "caption": "string",
  "tags": ["string"],
  "reactions": {"user_id": "reaction_type"},
  "comments": [
    {
      "user_id": "string",
      "username": "string",
      "text": "string",
      "timestamp": "string"
    }
  ],
  "username": "string",
  "profile_picture": "string | null"
}
```
- 404 Not Found: `{"message": "Post not found"}`
- 500 Internal Server Error: `{"message": "Error fetching post details"}`

### DELETE /post/<post_id>

**Description**: Delete a post.

**Response**:
- 200 OK: `{"message": "Post deleted successfully"}`
- 404 Not Found: `{"message": "Post not found"}`
- 403 Forbidden: `{"message": "Unauthorized to delete this post"}`
- 500 Internal Server Error: `{"message": "Error deleting post"}`

### POST /post/<post_id>/comment

**Description**: Add a comment to a post.

**Request Body**:
```json
{
  "text": "string"
}
```

**Response**:
- 201 Created: `{"message": "Comment added successfully", "comment": {"user_id": "string", "username": "string", "text": "string", "timestamp": "string"}}`
- 400 Bad Request: `{"message": "Comment text is required"}`
- 500 Internal Server Error: `{"message": "Error adding comment"}`

### DELETE /post/<post_id>/comment/<comment_timestamp>

**Description**: Delete a comment from a post.

**Response**:
- 200 OK: `{"message": "Comment deleted successfully"}`
- 404 Not Found: `{"message": "Comment not found"}`
- 403 Forbidden: `{"message": "Unauthorized to delete this comment"}`
- 500 Internal Server Error: `{"message": "Error deleting comment"}`

### POST /react/<post_id>

**Description**: Add or change a reaction to a post.

**Request Body**:
```json
{
  "reaction": "string"
}
```

**Response**:
- 200 OK: `{"message": "Reaction updated successfully", "reactions": {"user_id": "reaction_type"}}`
- 400 Bad Request: `{"message": "Reaction type is required"}`
- 404 Not Found: `{"message": "Post not found"}`
- 500 Internal Server Error: `{"message": "Error updating reaction"}`

## Admin Management

### GET /admin/panel

**Description**: Get all users and posts (admin only).

**Response**:
- 200 OK: 
```json
{
  "users": [
    {
      "_id": "string",
      "username": "string",
      "followers": "number",
      "following": "number",
      "role": "string"
    }
  ],
  "posts": [
    {
      "_id": "string",
      "user_id": "string",
      "caption": "string",
      "image_url": "string"
    }
  ]
}
```
- 403 Forbidden: `{"message": "Unauthorized access"}`
- 500 Internal Server Error: `{"message": "Error fetching admin panel data"}`

### GET /admin/user/<user_id>

**Description**: View user activity logs and posts (admin only).

**Response**:
- 200 OK: 
```json
{
  "user": {
    "_id": "string",
    "username": "string",
    "followers": "number",
    "following": "number",
    "profile_bio": "string",
    "profile_picture": "string | null"
  },
  "logs": [
    {
      "_id": "string",
      "action": "string",
      "timestamp": "string"
    }
  ],
  "posts": [
    {
      "_id": "string",
      "image_url": "string",
      "caption": "string",
      "tags": ["string"],
      "timestamp": "string"
    }
  ]
}
```
- 403 Forbidden: `{"message": "Unauthorized access"}`
- 500 Internal Server Error: `{"message": "Error fetching user details"}`

### POST /admin/promote/<user_id>

**Description**: Promote a user to admin (admin only).

**Response**:
- 200 OK: `{"message": "User promoted to admin successfully"}`
- 500 Internal Server Error: `{"message": "Error promoting user"}`

### POST /admin/demote/<user_id>

**Description**: Demote a user from admin (admin only).

**Response**:
- 200 OK: `{"message": "User demoted from admin successfully"}`
- 403 Forbidden: `{"message": "Unauthorized access"}`
- 500 Internal Server Error: `{"message": "Error demoting user"}`

### DELETE /admin/delete_user/<user_id>

**Description**: Delete a user and their posts (admin only).

**Response**:
- 200 OK: `{"message": "User and their posts deleted successfully"}`
- 403 Forbidden: `{"message": "Unauthorized access"}`
- 500 Internal Server Error: `{"message": "Error deleting user"}`

### DELETE /admin/delete_post/<post_id>

**Description**: Delete a post (admin only).

**Response**:
- 200 OK: `{"message": "Post deleted successfully"}`
- 403 Forbidden: `{"message": "Unauthorized access"}`
- 500 Internal Server Error: `{"message": "Error deleting post"}`

### GET /admin/check

**Description**: Check admin status (admin only).

**Response**:
- 200 OK: `{"isAdmin": "boolean"}`
- 500 Internal Server Error: `{"message": "Error checking admin status"}`

## Search

### GET /search

**Description**: Search for users and posts.

**Query Parameters**:
- `q`: string (search query)
- `type`: string (optional, 'all', 'users', 'tags')

**Response**:
- 200 OK: 
```json
{
  "users": [
    {
      "_id": "string",
      "username": "string",
      "profile_picture": "string | null",
      "followers": "number",
      "following": "number"
    }
  ],
  "posts": [
    {
      "_id": "string",
      "user_id": "string",
      "username": "string",
      "image_url": "string",
      "caption": "string",
      "tags": ["string"]
    }
  ]
}
```
- 500 Internal Server Error: `{"message": "Error performing search"}`

## Static Files

### GET /uploads/<path:filename>

**Description**: Serve uploaded files.

**Response**:
- 200 OK: File content
- 401 Unauthorized: `{"message": "Missing Authorization Header"}`

### GET /uploads/profile_pictures/<path:filename>

**Description**: Serve profile pictures.

**Response**:
- 200 OK: File content
- 401 Unauthorized: `{"message": "Missing Authorization Header"}`

### GET /images/<path:filename>

**Description**: Serve image files.

**Response**:
- 200 OK: File content
- 401 Unauthorized: `{"message": "Missing Authorization Header"}`

### GET /api/images/default_avatar

**Description**: Serve default avatar.

**Response**:
- 200 OK: File content
- 401 Unauthorized: `{"message": "Missing Authorization Header"}`
