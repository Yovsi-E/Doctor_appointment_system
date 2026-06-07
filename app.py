import os
import re
import logging
import secrets
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_wtf.csrf import CSRFProtect, CSRFError
from dotenv import load_dotenv
import bcrypt

load_dotenv()

import database
import security

app = Flask(__name__)

# Development / Environment Configuration
app.config['ENV'] = os.environ.get('FLASK_ENV', 'production')
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', '0') == '1'

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB upload limit

# Secure Cookies Configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = not app.config['DEBUG']  # True in production (requires HTTPS)

# Enable CSRF Protection globally
csrf = CSRFProtect(app)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure Security Logging
log_file = os.path.join(os.path.dirname(__file__), 'security.log')

class SafeFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, 'client_ip'):
            record.client_ip = 'N/A'
        return super().format(record)

security_formatter = SafeFormatter('%(asctime)s [%(levelname)s] - IP: %(client_ip)s - %(message)s')
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.WARNING)
security_file_handler = logging.FileHandler(log_file)
security_file_handler.setFormatter(security_formatter)
security_logger.addHandler(security_file_handler)


def log_security_event(level, message):
    try:
        client_ip = request.remote_addr
    except Exception:
        client_ip = 'N/A'
    security_logger.log(level, message, extra={'client_ip': client_ip})

# Inactivity Handler
@app.before_request
def check_session_inactivity():
    # Exclude static assets
    if request.path.startswith('/static'):
        return

    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=15)
    
    # Check if user is logged in
    if 'user_id' in session:
        last_activity_str = session.get('last_activity')
        if last_activity_str:
            try:
                last_activity = datetime.fromisoformat(last_activity_str)
                now = datetime.now(timezone.utc)
                
                # If inactive for more than 15 minutes, force logout
                if now - last_activity > timedelta(minutes=15):
                    log_security_event(logging.WARNING, f"Session expired due to inactivity for user ID: {session.get('user_id')}")
                    session.clear()
                    flash("Your session has expired due to inactivity. Please log in again.", "error")
                    return redirect(url_for('login', reason='inactivity'))
            except ValueError:
                session.clear()
                return redirect(url_for('login'))
                
        # Update last activity timestamp
        session['last_activity'] = datetime.now(timezone.utc).isoformat()

# CSRF Error handler
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    log_security_event(logging.ERROR, f"CSRF validation failed on {request.path}")
    flash("The session form validation expired. Please try again.", "error")
    return redirect(request.referrer or url_for('login'))

# API Authentication Helper (JWT + Session Fallback)
def get_authenticated_user():
    """
    Checks for JWT in Authorization Header, or falls back to standard Flask Session.
    Returns (user_id, role) if authenticated, or (None, None).
    """
    # 1. Check JWT Authorization Header
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        payload = security.decode_jwt_token(token)
        if payload:
            return payload['sub'], payload['role']
        else:
            log_security_event(logging.WARNING, "Invalid or expired JWT token presented")
            return None, None
            
    # 2. Check Session Cookies
    if 'user_id' in session:
        return session['user_id'], session['role']
        
    return None, None

# --- WEB UI VIEWS ---

@app.route('/')
def index():
    if 'user_id' in session:
        if session['role'] == 'patient':
            return redirect(url_for('dashboard'))
        elif session['role'] == 'doctor':
            return redirect(url_for('doctor_schedule'))
        elif session['role'] == 'admin':
            return redirect(url_for('admin_panel'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Form Validation
        if not name or not email or not phone or not password:
            flash("All fields are required.", "error")
            return render_template('register.html')
            
        if len(name) < 2:
            flash("Name is too short.", "error")
            return render_template('register.html')

        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            flash("Please enter a valid email address.", "error")
            return render_template('register.html')

        if not re.match(r"^\+?[0-9\s\-()]{7,20}$", phone):
            flash("Please enter a valid phone number.", "error")
            return render_template('register.html')

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template('register.html')

        # Validate Password Strength
        is_strong, strength_msg = security.is_password_strong(password)
        if not is_strong:
            flash(strength_msg, "error")
            return render_template('register.html')

        conn = database.get_db_connection()
        cursor = conn.cursor()

        # Check if user already exists
        cursor.execute("SELECT id FROM users WHERE email = ?;", (email,))
        if cursor.fetchone():
            conn.close()
            flash("An account with this email already exists.", "error")
            return render_template('register.html')

        # Hash Password
        salt = bcrypt.gensalt(rounds=12)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

        # Insert user
        try:
            cursor.execute("""
            INSERT INTO users (name, email, phone, password_hash, role)
            VALUES (?, ?, ?, ?, 'patient');
            """, (name, email, phone, hashed_password))
            conn.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            log_security_event(logging.ERROR, f"DB registration error: {str(e)}")
            flash("A database error occurred. Please try again.", "error")
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password')
        role = request.form.get('role', 'patient')

        if role not in ('patient', 'doctor', 'admin'):
            role = 'patient'

        conn = database.get_db_connection()
        
        # Rate limiting check
        client_ip = request.remote_addr
        if not security.check_rate_limit(conn, client_ip, 'login'):
            log_security_event(logging.WARNING, f"Rate limit exceeded for IP: {client_ip} trying to login as {email}")
            conn.close()
            flash("Too many failed attempts. Please try again in 15 minutes.", "error")
            return render_template('login.html')

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? AND role = ?;", (email, role))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            # Successful Login - Session Fixation Prevention
            session.clear()
            session['user_id'] = user['id']
            session['name'] = user['name']
            session['role'] = user['role']
            session['last_activity'] = datetime.now(timezone.utc).isoformat()
            
            # Log login attempt success
            security.log_login_attempt(conn, email, client_ip, success=True)
            conn.close()
            
            log_security_event(logging.WARNING, f"User {email} (ID: {user['id']}) logged in successfully as {role}")
            
            if role == 'patient':
                return redirect(url_for('dashboard'))
            elif role == 'doctor':
                return redirect(url_for('doctor_schedule'))
            else:
                return redirect(url_for('admin_panel'))
        else:
            # Failed Login
            security.log_login_attempt(conn, email, client_ip, success=False)
            conn.close()
            
            log_security_event(logging.WARNING, f"Failed login attempt for email: {email} as {role}")
            flash("Invalid email or password.", "error")

    return render_template('login.html')

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_security_event(logging.WARNING, f"User ID {user_id} logged out.")
    
    session.clear()
    
    if request.args.get('reason') == 'inactivity':
        flash("You have been logged out due to inactivity.", "error")
    else:
        flash("You have been logged out successfully.", "success")
        
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    # Authentication check
    if 'user_id' not in session or session.get('role') != 'patient':
        return redirect(url_for('login'))

    search_query = request.args.get('search', '').strip()
    # Sanitize search query
    clean_search = security.sanitize_text(search_query)

    conn = database.get_db_connection()
    cursor = conn.cursor()

    # Search doctors if requested
    doctors = []
    if clean_search:
        cursor.execute("""
        SELECT id, name, phone FROM users 
        WHERE role = 'doctor' AND (name LIKE ? OR email LIKE ?);
        """, (f"%{clean_search}%", f"%{clean_search}%"))
        doctors = cursor.fetchall()

    # Retrieve patient's appointments
    cursor.execute("""
    SELECT a.id, a.date, a.time_slot, a.reason, a.document_path, u.name as doctor_name
    FROM appointments a
    JOIN users u ON a.doctor_id = u.id
    WHERE a.patient_id = ?
    ORDER BY a.date ASC, a.time_slot ASC;
    """, (session['user_id'],))
    appointments = cursor.fetchall()
    conn.close()

    return render_template('dashboard.html', 
                           appointments=appointments, 
                           doctors=doctors, 
                           search_query=clean_search)

@app.route('/book', methods=['GET', 'POST'])
def book():
    # Authentication check
    if 'user_id' not in session or session.get('role') != 'patient':
        return redirect(url_for('login'))

    conn = database.get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        date_str = request.form.get('date', '').strip()
        time_slot = request.form.get('time_slot', '').strip()
        reason = request.form.get('reason', '').strip()

        # Sanitize symptoms/reason field against XSS/HTML Injection
        clean_reason = security.sanitize_text(reason)

        # Basic validations
        if not doctor_id or not date_str or not time_slot or not clean_reason:
            flash("All booking fields are required.", "error")
            conn.close()
            return redirect(url_for('book'))

        # Date validations (no past dates, weekdays only)
        try:
            booking_date = datetime.strptime(date_str, "%Y-%m-%d").date()
            if booking_date < datetime.now(timezone.utc).date():
                flash("Cannot book appointments in the past.", "error")
                conn.close()
                return redirect(url_for('book'))
            
            # Weekday check
            if booking_date.weekday() in (5, 6):
                flash("Appointments can only be booked on weekdays.", "error")
                conn.close()
                return redirect(url_for('book'))
        except ValueError:
            flash("Invalid date format.", "error")
            conn.close()
            return redirect(url_for('book'))

        # Verify time slot structure
        if time_slot not in ["09:00 AM", "09:30 AM", "10:00 AM", "10:30 AM", 
                             "11:00 AM", "11:30 AM", "02:00 PM", "02:30 PM", 
                             "03:00 PM", "03:30 PM", "04:00 PM", "04:30 PM"]:
            flash("Invalid time slot selected.", "error")
            conn.close()
            return redirect(url_for('book'))

        # Handle File Upload
        document_path = None
        file = request.files.get('document')
        if file and file.filename != '':
            is_valid_file, file_result = security.validate_uploaded_file(file)
            if not is_valid_file:
                flash(file_result, "error")
                log_security_event(logging.WARNING, f"Rejected file upload attempt: {file_result}")
                conn.close()
                return redirect(url_for('book'))
            
            # Secure upload save
            safe_filename = f"{int(datetime.now(timezone.utc).timestamp())}_{file_result}"
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
            file.save(save_path)
            document_path = safe_filename
            log_security_event(logging.WARNING, f"Patient {session['user_id']} uploaded medical document: {safe_filename}")

        # Double-booking DB validation (race condition prevention)
        cursor.execute("""
        SELECT id FROM appointments 
        WHERE doctor_id = ? AND date = ? AND time_slot = ?;
        """, (doctor_id, date_str, time_slot))
        
        if cursor.fetchone():
            flash("This time slot has already been booked. Please choose another.", "error")
            conn.close()
            return redirect(url_for('book'))

        # Complete Booking
        try:
            cursor.execute("""
            INSERT INTO appointments (patient_id, doctor_id, date, time_slot, reason, document_path)
            VALUES (?, ?, ?, ?, ?, ?);
            """, (session['user_id'], doctor_id, date_str, time_slot, clean_reason, document_path))
            conn.commit()
            
            # Email Confirmation Stub (Security requirement / Bonus feature)
            print(f"\n[EMAIL STUB] Sending appointment confirmation email to Patient ID {session['user_id']}:")
            print(f"Details: Consultation with Doctor ID {doctor_id} scheduled for {date_str} at {time_slot}.\n")
            
            flash("Appointment booked successfully!", "success")
            conn.close()
            return redirect(url_for('dashboard'))
        except Exception as e:
            log_security_event(logging.ERROR, f"DB booking error: {str(e)}")
            flash("Database booking failed. Please try again.", "error")
            conn.close()
            return redirect(url_for('book'))

    # GET Request
    cursor.execute("SELECT id, name FROM users WHERE role = 'doctor';")
    doctors = cursor.fetchall()
    conn.close()
    
    selected_doctor_id = request.args.get('doctor_id', '')
    return render_template('book.html', doctors=doctors, selected_doctor_id=selected_doctor_id)

@app.route('/doctor/schedule')
def doctor_schedule():
    # Authentication check
    if 'user_id' not in session or session.get('role') != 'doctor':
        return redirect(url_for('login'))

    selected_date = request.args.get('date', '').strip()
    if not selected_date:
        selected_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Basic Date format validation
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", selected_date):
        selected_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    conn = database.get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT a.id, a.time_slot, a.reason, a.document_path, u.name as patient_name, u.phone
    FROM appointments a
    JOIN users u ON a.patient_id = u.id
    WHERE a.doctor_id = ? AND a.date = ?
    ORDER BY a.time_slot ASC;
    """, (session['user_id'], selected_date))
    appointments = cursor.fetchall()
    conn.close()

    return render_template('doctor_schedule.html', appointments=appointments, selected_date=selected_date)

@app.route('/view_document/<int:appointment_id>')
def view_document(appointment_id):
    # Authorization checks
    if 'user_id' not in session:
        log_security_event(logging.ERROR, f"Unauthorized file view attempt of appt {appointment_id}")
        return "Unauthorized", 401

    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT patient_id, doctor_id, document_path FROM appointments WHERE id = ?;", (appointment_id,))
    appt = cursor.fetchone()
    conn.close()

    if not appt:
        return "File not found", 404

    # Access Control Enforcement
    curr_user = session['user_id']
    curr_role = session['role']
    
    # User must be the patient who booked or the doctor assigned
    if (curr_role == 'patient' and appt['patient_id'] != curr_user) or \
       (curr_role == 'doctor' and appt['doctor_id'] != curr_user):
        log_security_event(logging.ERROR, f"User {curr_user} ({curr_role}) denied access to file of appt {appointment_id}")
        return "Access Denied", 403

    if not appt['document_path']:
        return "No document uploaded for this appointment.", 404

    # Serve file securely, bypassing directory traversal attacks using send_from_directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], appt['document_path'], as_attachment=True)

@app.route('/cancel/<int:appointment_id>', methods=['POST'])
def cancel_appointment(appointment_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT patient_id, doctor_id, date, time_slot FROM appointments WHERE id = ?;",
        (appointment_id,)
    )
    appt = cursor.fetchone()

    if not appt:
        conn.close()
        flash("Appointment not found.", "error")
        return redirect(url_for('dashboard'))

    if session['role'] != 'patient' or appt['patient_id'] != session['user_id']:
        conn.close()
        flash("Unauthorized action.", "error")
        return redirect(url_for('dashboard'))

    try:
        cursor.execute("DELETE FROM appointments WHERE id = ?;", (appointment_id,))
        conn.commit()
        flash("Appointment cancelled successfully.", "success")
    except Exception as e:
        log_security_event(logging.ERROR, f"DB cancel error: {str(e)}")
        flash("Failed to cancel appointment.", "error")
    finally:
        conn.close()

    return redirect(url_for('dashboard'))


# --- SECURE JSON API ENDPOINTS ---

@app.route('/api/token', methods=['POST'])
@csrf.exempt  # Exempt from CSRF as API clients use Token auth
def get_api_token():
    """
    Authenticate user and return a secure JWT token.
    JSON Payload: { "email": "...", "password": "...", "role": "..." }
    """
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    password = data.get('password')
    role = data.get('role', 'patient')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ? AND role = ?;", (email, role))
    user = cursor.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        token = security.generate_jwt_token(user['id'], user['role'])
        return jsonify({"token": token, "expires_in_hours": 2})
    else:
        log_security_event(logging.WARNING, f"Failed API token request for: {email}")
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/appointments', methods=['GET'])
@csrf.exempt  # APIs exempt from CSRF
def api_appointments():
    """
    Returns appointment data.
    If Patient: returns list of patient's own bookings.
    If query filters doctor_id & date: returns doctor's booked slots (unrestricted to allow booking check).
    """
    # 1. Check if checking slots (doctor_id + date filters)
    doc_filter = request.args.get('doctor_id')
    date_filter = request.args.get('date')
    
    if doc_filter and date_filter:
        # Sanitization
        clean_date = security.sanitize_text(date_filter)
        conn = database.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        SELECT time_slot FROM appointments 
        WHERE doctor_id = ? AND date = ?;
        """, (doc_filter, clean_date))
        slots = cursor.fetchall()
        conn.close()
        
        return jsonify({"appointments": [{"time_slot": s['time_slot']} for s in slots]})

    # 2. General endpoint for patient to view bookings
    user_id, role = get_authenticated_user()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    if role != 'patient':
        return jsonify({"error": "Forbidden - Patient access only"}), 403

    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT a.id, a.date, a.time_slot, a.reason, u.name as doctor_name
    FROM appointments a
    JOIN users u ON a.doctor_id = u.id
    WHERE a.patient_id = ?
    ORDER BY a.date ASC;
    """, (user_id,))
    appts = cursor.fetchall()
    conn.close()

    result = []
    for a in appts:
        result.append({
            "id": a['id'],
            "date": a['date'],
            "time_slot": a['time_slot'],
            "reason": a['reason'],
            "doctor": a['doctor_name']
        })

    return jsonify({"appointments": result})

@app.route('/api/doctor/schedule', methods=['GET'])
@csrf.exempt
def api_doctor_schedule():
    """
    Returns doctor's appointment list for a specified date.
    Requires Doctor role authentication.
    """
    user_id, role = get_authenticated_user()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    if role != 'doctor':
        return jsonify({"error": "Forbidden - Doctor access only"}), 403

    date_str = request.args.get('date', '').strip()
    if not date_str:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Sanitize date format
    clean_date = security.sanitize_text(date_str)

    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT a.id, a.time_slot, a.reason, u.name as patient_name, u.phone
    FROM appointments a
    JOIN users u ON a.patient_id = u.id
    WHERE a.doctor_id = ? AND a.date = ?
    ORDER BY a.time_slot ASC;
    """, (user_id, clean_date))
    appts = cursor.fetchall()
    conn.close()

    result = []
    for a in appts:
        result.append({
            "id": a['id'],
            "time_slot": a['time_slot'],
            "reason": a['reason'],
            "patient": a['patient_name'],
            "phone": a['phone']
        })

    return jsonify({"date": clean_date, "schedule": result})

@app.route('/api/appointments/book', methods=['POST'])
@csrf.exempt
def api_appointments_book():
    """
    Allows booking an appointment via JSON payload.
    Requires Patient role authentication.
    """
    user_id, role = get_authenticated_user()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    if role != 'patient':
        return jsonify({"error": "Forbidden - Patient access only"}), 403

    data = request.get_json() or {}
    doctor_id = data.get('doctor_id')
    date_str = data.get('date', '').strip()
    time_slot = data.get('time_slot', '').strip()
    reason = data.get('reason', '').strip()

    if not doctor_id or not date_str or not time_slot or not reason:
        return jsonify({"error": "Missing required fields"}), 400

    # Sanitize
    clean_reason = security.sanitize_text(reason)

    # Date validations
    try:
        booking_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        if booking_date < datetime.now(timezone.utc).date():
            return jsonify({"error": "Cannot book appointments in the past"}), 400
        if booking_date.weekday() in (5, 6):
            return jsonify({"error": "Appointments can only be booked on weekdays"}), 400
    except ValueError:
        return jsonify({"error": "Invalid date format"}), 400

    conn = database.get_db_connection()
    cursor = conn.cursor()

    # Check slot taken
    cursor.execute("""
    SELECT id FROM appointments 
    WHERE doctor_id = ? AND date = ? AND time_slot = ?;
    """, (doctor_id, date_str, time_slot))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": "Time slot already taken"}), 400

    # Save booking
    try:
        cursor.execute("""
        INSERT INTO appointments (patient_id, doctor_id, date, time_slot, reason, document_path)
        VALUES (?, ?, ?, ?, ?, NULL);
        """, (user_id, doctor_id, date_str, time_slot, clean_reason))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Appointment booked successfully"}), 201
    except Exception as e:
        log_security_event(logging.ERROR, f"API DB booking error: {str(e)}")
        conn.close()
        return jsonify({"error": "Database error"}), 500

@app.route('/api/appointments/<int:appointment_id>', methods=['DELETE'])
@csrf.exempt
def api_appointments_cancel(appointment_id):
    user_id, role = get_authenticated_user()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT patient_id FROM appointments WHERE id = ?;",
        (appointment_id,)
    )
    appt = cursor.fetchone()

    if not appt:
        conn.close()
        return jsonify({"error": "Appointment not found"}), 404

    if appt['patient_id'] != user_id:
        conn.close()
        return jsonify({"error": "Forbidden"}), 403

    try:
        cursor.execute("DELETE FROM appointments WHERE id = ?;", (appointment_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Appointment cancelled"}), 200
    except Exception as e:
        log_security_event(logging.ERROR, f"API cancel error: {str(e)}")
        conn.close()
        return jsonify({"error": "Database error"}), 500


# --- ADMIN ROUTES ---

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email, phone, created_at FROM users WHERE role = 'doctor' ORDER BY name;")
    doctors = cursor.fetchall()
    conn.close()

    return render_template('admin.html', doctors=doctors)


@app.route('/admin/add_doctor', methods=['POST'])
def add_doctor():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    phone = request.form.get('phone', '').strip()
    password = request.form.get('password', '')

    if not name or not email or not phone or not password:
        flash("All fields are required.", "error")
        return redirect(url_for('admin_panel'))

    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?;", (email,))
    if cursor.fetchone():
        conn.close()
        flash("A user with this email already exists.", "error")
        return redirect(url_for('admin_panel'))

    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    try:
        cursor.execute("""
        INSERT INTO users (name, email, phone, password_hash, role)
        VALUES (?, ?, ?, ?, 'doctor');
        """, (name, email, phone, hashed))
        conn.commit()
        flash(f"Doctor '{name}' added successfully.", "success")
    except Exception as e:
        log_security_event(logging.ERROR, f"DB add_doctor error: {str(e)}")
        flash("Failed to add doctor.", "error")
    finally:
        conn.close()

    return redirect(url_for('admin_panel'))


@app.route('/admin/delete_doctor/<int:doctor_id>', methods=['POST'])
def delete_doctor(doctor_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM users WHERE id = ? AND role = 'doctor';", (doctor_id,))
    doctor = cursor.fetchone()

    if not doctor:
        conn.close()
        flash("Doctor not found.", "error")
        return redirect(url_for('admin_panel'))

    try:
        cursor.execute("DELETE FROM appointments WHERE doctor_id = ?;", (doctor_id,))
        cursor.execute("DELETE FROM users WHERE id = ? AND role = 'doctor';", (doctor_id,))
        conn.commit()
        flash(f"Doctor '{doctor['name']}' and their appointments deleted.", "success")
    except Exception as e:
        log_security_event(logging.ERROR, f"DB delete_doctor error: {str(e)}")
        flash("Failed to delete doctor.", "error")
    finally:
        conn.close()

    return redirect(url_for('admin_panel'))


# Initialize database on startup
try:
    database.init_db()
except Exception as e:
    import logging as _logging
    _logging.getLogger('security').error(f"Database init failed: {e}")

# Health check endpoint for Render
@app.route('/health')
def health():
    try:
        conn = database.get_db_connection()
        conn.close()
        return jsonify({"status": "healthy", "db": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

if __name__ == '__main__':
    # Running locally - Secure configurations
    # Host 127.0.0.1 is selected so it binds locally and remains protected
    debug = app.config['DEBUG']
    app.run(host='127.0.0.1', port=5000, debug=debug, use_reloader=debug)
