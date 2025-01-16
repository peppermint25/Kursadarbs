from flask import current_app
import os
from werkzeug.utils import secure_filename
import uuid

# ...existing code...

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

@profile_bp.route('/upload_profile_picture', methods=['POST'])
@jwt_required()
def upload_profile_picture():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    if file and allowed_file(file.filename):
        # Generate unique filename
        filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
        file_path = os.path.join(current_app.config['IMAGES_FOLDER'], filename)
        
        # Save file
        file.save(file_path)
        
        # Update user profile in database
        user_id = get_jwt_identity()
        profile_picture_url = f'/images/{filename}'
        
        # Update in database
        db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'profile_picture': profile_picture_url}}
        )
        
        return jsonify({
            'message': 'Profile picture updated',
            'profile_picture': profile_picture_url
        })
        
    return jsonify({'error': 'Invalid file type'}), 400

# ...existing code...
