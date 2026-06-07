import os
import re
import secrets
import bleach
import jwt
import datetime
from werkzeug.utils import secure_filename

# Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2MB

# Magic bytes (file signatures) mapping
FILE_SIGNATURES = {
    b'%PDF': 'pdf',
    b'\xff\xd8\xff': 'jpg',
    b'\x89PNG\r\n\x1a\n': 'png'
}

def is_password_strong(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Password is strong."

def sanitize_text(text):
    if not text:
        return ""
    # Strip all HTML tags entirely for inputs like visit reason or doctor search
    return bleach.clean(text, tags=[], attributes={}, strip=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_uploaded_file(file_storage):
    """
    Validates Flask FileStorage object.
    Checks size, file extension, secure filename, and magic byte signature.
    Returns (is_valid, filename_or_error_msg)
    """
    if not file_storage or file_storage.filename == '':
        return False, "No file selected."
    
    # 1. Check extension
    filename = file_storage.filename
    if not allowed_file(filename):
        return False, "Invalid file extension. Only PDF, JPG, JPEG, and PNG are allowed."
    
    # Secure the filename
    safe_filename = secure_filename(filename)
    if not safe_filename:
        return False, "Invalid filename."
    
    # 2. Check size (read stream up to limit + 1)
    file_storage.seek(0, os.SEEK_END)
    size = file_storage.tell()
    file_storage.seek(0)  # Reset stream pointer
    
    if size > MAX_CONTENT_LENGTH:
        return False, "File exceeds the 2MB size limit."
        
    # 3. Check file signature (magic bytes)
    header = file_storage.read(16)
    file_storage.seek(0)  # Reset stream pointer after reading
    
    matched = False
    for signature, filetype in FILE_SIGNATURES.items():
        if header.startswith(signature):
            matched = True
            break
            
    if not matched:
        return False, "File content does not match its extension (possible spoofed file type)."
        
    return True, safe_filename

# Database rate limiter helper
def check_rate_limit(conn, ip_address, action, limit=5, period_seconds=900):
    """
    Checks if an IP address has exceeded rate limits for an action.
    Returns True if allowed, False if blocked.
    Uses Python-computed timestamps (database-agnostic).
    """
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=period_seconds)
    cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

    cursor = conn.cursor()
    # Remove older attempts to save space
    cursor.execute("""
    DELETE FROM login_attempts 
    WHERE timestamp < ?;
    """, (cutoff_str,))
    
    # Count attempts in the active window
    cursor.execute("""
    SELECT COUNT(*) FROM login_attempts
    WHERE ip_address = ? AND success = 0 AND timestamp >= ?;
    """, (ip_address, cutoff_str))
    
    row = cursor.fetchone()
    if row is None:
        return True
    if hasattr(row, 'values'):
        count = list(row.values())[0]
    elif isinstance(row, (tuple, list)):
        count = row[0]
    else:
        count = list(dict(row).values())[0]
    return count < limit

def log_login_attempt(conn, email, ip_address, success):
    """
    Logs login attempts in the database.
    """
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO login_attempts (email, ip_address, success)
    VALUES (?, ?, ?);
    """, (email, ip_address, 1 if success else 0))
    conn.commit()

# JWT Helpers
def generate_jwt_token(user_id, role):
    payload = {
        'sub': str(user_id),
        'role': role,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
