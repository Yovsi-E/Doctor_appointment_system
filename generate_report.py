from fpdf import FPDF
from datetime import datetime


class Report(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 16)
        self.set_text_color(25, 50, 100)
        self.cell(0, 10, 'Doctor Appointment System', new_x='LMARGIN', new_y='NEXT', align='C')
        self.set_font('Helvetica', 'I', 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, 'Technical Report & Implementation Guide', new_x='LMARGIN', new_y='NEXT', align='C')
        self.line(10, self.get_y() + 2, 200, self.get_y() + 2)
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', align='C')

    def section_title(self, title):
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(25, 50, 100)
        self.cell(0, 10, title, new_x='LMARGIN', new_y='NEXT')
        self.set_draw_color(25, 50, 100)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def sub_title(self, title):
        self.set_font('Helvetica', 'B', 12)
        self.set_text_color(50, 75, 125)
        self.cell(0, 8, title, new_x='LMARGIN', new_y='NEXT')
        self.ln(1)

    def body_text(self, text):
        self.set_font('Helvetica', '', 10)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 5.5, text)
        self.ln(1)

    def bullet(self, text):
        self.set_font('Helvetica', '', 10)
        self.set_text_color(40, 40, 40)
        self.cell(5)
        self.cell(4, 5.5, '-')
        self.multi_cell(0, 5.5, text)
        self.ln(0.5)

    def code_block(self, text):
        self.set_font('Courier', '', 8.5)
        self.set_fill_color(240, 240, 245)
        self.set_text_color(30, 30, 30)
        lines = text.split('\n')
        for line in lines:
            self.set_x(14)
            self.cell(182, 4.5, line, fill=True, new_x='LMARGIN', new_y='NEXT')
        self.ln(3)


pdf = Report()
pdf.alias_nb_pages()
pdf.set_auto_page_break(auto=True, margin=20)
pdf.add_page()

# --- TITLE PAGE ---
pdf.ln(30)
pdf.set_font('Helvetica', 'B', 28)
pdf.set_text_color(25, 50, 100)
pdf.cell(0, 14, 'Doctor Appointment System', new_x='LMARGIN', new_y='NEXT', align='C')
pdf.set_font('Helvetica', 'I', 14)
pdf.set_text_color(100, 100, 100)
pdf.cell(0, 8, 'A Secure Web Application for Medical Booking', new_x='LMARGIN', new_y='NEXT', align='C')
pdf.ln(6)
pdf.set_draw_color(25, 50, 100)
pdf.line(60, pdf.get_y(), 150, pdf.get_y())
pdf.ln(10)
pdf.set_font('Helvetica', '', 11)
pdf.set_text_color(60, 60, 60)
pdf.cell(0, 7, f'Generated: {datetime.now().strftime("%B %d, %Y")}', new_x='LMARGIN', new_y='NEXT', align='C')
pdf.cell(0, 7, 'Platform: Render Cloud (PostgreSQL + Gunicorn)', new_x='LMARGIN', new_y='NEXT', align='C')
pdf.cell(0, 7, 'Framework: Flask 3.x (Python)', new_x='LMARGIN', new_y='NEXT', align='C')
pdf.ln(15)

# --- TABLE OF CONTENTS ---
pdf.section_title('Table of Contents')
toc = [
    '1. Introduction & Objectives',
    '2. System Architecture',
    '3. Database Design & Schema',
    '4. Core Features & Implementation',
    '   4.1 User Authentication (Registration & Login)',
    '   4.2 Patient Dashboard & Doctor Search',
    '   4.3 Appointment Booking with Document Upload',
    '   4.4 Doctor Schedule Management',
    '   4.5 Appointment Cancellation',
    '5. Security Architecture',
    '   5.1 Password Security & Strength Enforcement',
    '   5.2 CSRF Protection',
    '   5.3 Input Sanitization (XSS Prevention)',
    '   5.4 Rate Limiting & Brute-Force Protection',
    '   5.5 Session Management & Inactivity Timeout',
    '   5.6 JWT-Based API Authentication',
    '   5.7 File Upload Security (Magic Byte Validation)',
    '   5.8 Access Control & Authorization',
    '6. REST API Design',
    '7. Frontend Design & UX',
    '8. Deployment on Render',
    '9. Technologies & Dependencies',
    '10. Conclusion'
]
for item in toc:
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(8)
    pdf.cell(0, 6, item, new_x='LMARGIN', new_y='NEXT')
pdf.add_page()

# --- 1. INTRODUCTION ---
pdf.section_title('1. Introduction & Objectives')
pdf.body_text(
    'The Doctor Appointment System is a full-stack web application designed to streamline the process '
    'of booking medical consultations. It provides two distinct user portals: a Patient Portal for '
    'searching doctors, booking appointments, and uploading medical documents, and a Doctor Portal '
    'for viewing daily schedules and accessing patient-submitted clinical documents.'
)
pdf.body_text(
    'The system was built with security as a foundational principle. Every endpoint enforces '
    'role-based access control, all user inputs are sanitized against injection attacks, file uploads '
    'are validated at the binary level, and session tokens are protected with best-practice cookie flags. '
    'The application was deployed on Render cloud infrastructure using PostgreSQL and Gunicorn for '
    'production-grade reliability.'
)
pdf.body_text('Key objectives achieved:')
pdf.bullet('Dual-role portal with distinct patient and doctor workflows')
pdf.bullet('Secure appointment booking with real-time slot availability')
pdf.bullet('Medical document upload with validation at the file signature (magic byte) level')
pdf.bullet('RESTful JSON API for external client integration')
pdf.bullet('Comprehensive security: CSRF, rate limiting, XSS sanitization, JWT, session timeout')
pdf.bullet('Cloud deployment with automatic horizontal scaling and managed PostgreSQL')
pdf.ln(4)

# --- 2. SYSTEM ARCHITECTURE ---
pdf.section_title('2. System Architecture')
pdf.body_text(
    'The application follows a Model-View-Controller (MVC) pattern implemented with Flask. The '
    'architecture is organized into four primary layers:'
)
pdf.bullet('Presentation Layer (Templates): Jinja2 templates with a glassmorphism dark theme '
           'providing responsive HTML5 interfaces for login, registration, dashboard, booking, and '
           'doctor schedule views.')
pdf.bullet('Business Logic Layer (app.py): Central Flask application handling routing, form '
           'validation, session management, and access control enforcement for 15 routes.')
pdf.bullet('Data Access Layer (database.py): Abstracted database interface with DbConnection and '
           'DbCursor wrappers that transparently convert SQLite parameter syntax to PostgreSQL, '
           'providing seamless dual-database support.')
pdf.bullet('Security Layer (security.py): Cross-cutting security module providing password hashing, '
           'input sanitization (Bleach), JWT token generation/validation, rate limiting, and file '
           'upload validation.')
pdf.body_text(
    'The application supports two database backends: SQLite for local development and PostgreSQL '
    'for production on Render. The DbCursor wrapper automatically converts "?" placeholders to '
    '"%s" when PostgreSQL is detected via the DATABASE_URL environment variable, allowing the '
    'same codebase to run in both environments without modification.'
)
pdf.ln(2)

# --- 3. DATABASE DESIGN ---
pdf.section_title('3. Database Design & Schema')
pdf.body_text(
    'The database consists of three relational tables with foreign key constraints and unique '
    'indexes ensuring data integrity:'
)

pdf.sub_title('3.1 Users Table')
pdf.code_block(
    '  id             INTEGER PRIMARY KEY AUTOINCREMENT (SQLite)\n'
    '                 SERIAL PRIMARY KEY (PostgreSQL)\n'
    '  name           TEXT NOT NULL\n'
    '  email          TEXT UNIQUE NOT NULL\n'
    '  phone          TEXT NOT NULL\n'
    '  password_hash  TEXT NOT NULL       -- bcrypt hashed (12 rounds)\n'
    '  role           TEXT NOT NULL CHECK(role IN (''patient'', ''doctor''))\n'
    '  created_at     DATETIME DEFAULT CURRENT_TIMESTAMP'
)
pdf.body_text(
    'The users table stores both patient and doctor accounts. The role column enforces a strict '
    'check constraint limiting values to "patient" or "doctor". Passwords are never stored in '
    'plaintext; they are hashed using bcrypt with a work factor of 12 rounds before storage.'
)

pdf.sub_title('3.2 Appointments Table')
pdf.code_block(
    '  id             INTEGER PRIMARY KEY AUTOINCREMENT\n'
    '  patient_id     INTEGER NOT NULL  -- FK -> users(id)\n'
    '  doctor_id      INTEGER NOT NULL  -- FK -> users(id)\n'
    '  date           TEXT NOT NULL      -- YYYY-MM-DD format\n'
    '  time_slot      TEXT NOT NULL      -- e.g. "10:00 AM"\n'
    '  reason         TEXT NOT NULL      -- Sanitized visit reason\n'
    '  document_path  TEXT               -- Optional uploaded file\n'
    '  created_at     DATETIME DEFAULT CURRENT_TIMESTAMP\n'
    '  UNIQUE(doctor_id, date, time_slot) -- Prevent double-booking'
)
pdf.body_text(
    'The appointments table enforces a unique constraint on (doctor_id, date, time_slot) to prevent '
    'race conditions where two patients could book the same slot simultaneously. The database-level '
    'constraint serves as the final safety net after application-level validation.'
)

pdf.sub_title('3.3 Login Attempts Table')
pdf.code_block(
    '  id             INTEGER PRIMARY KEY AUTOINCREMENT\n'
    '  email          TEXT NOT NULL\n'
    '  ip_address     TEXT NOT NULL\n'
    '  timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP\n'
    '  success        INTEGER NOT NULL CHECK(success IN (0, 1))'
)
pdf.body_text(
    'This table powers the rate limiting system. Failed login attempts are logged with their IP '
    'address and timestamp. The check_rate_limit function queries this table to determine if an IP '
    'has exceeded the threshold (5 failures in 15 minutes).'
)
pdf.add_page()

# --- 4. CORE FEATURES ---
pdf.section_title('4. Core Features & Implementation')

pdf.sub_title('4.1 User Authentication (Registration & Login)')
pdf.body_text(
    'Registration (POST /register): New patients complete a multi-field form (name, email, phone, '
    'password). The form enforces client-side validation via JavaScript (real-time password strength '
    'indicator with 5 criteria: length >= 8, lowercase, uppercase, digit, special character) and '
    'server-side validation in Python using regex patterns. Passwords are hashed with bcrypt '
    '(gensalt with 12 rounds) before storage. Duplicate email detection prevents multiple accounts.'
)
pdf.body_text(
    'Login (POST /login): The login page features a role tab-switcher (Patient/Doctor). Credentials '
    'are validated against the database using bcrypt.checkpw(). On success, the session is cleared '
    '(preventing session fixation attacks), then populated with user_id, name, and role. A '
    'last_activity timestamp is set for inactivity tracking. Failed attempts are logged to the '
    'login_attempts table for rate limiting.'
)
pdf.body_text(
    'As a practical example, a patient user "John Smith" would register with email '
    '"john@example.com" and password "StrongP@ss1", then log in to access the patient dashboard. '
    'A doctor such as "Dr. Alice Smith" logs in with "alice.smith@hospital.com" and the default '
    'seeded password "SecurePassword123!" to view their appointment schedule.'
)

pdf.sub_title('4.2 Patient Dashboard & Doctor Search')
pdf.body_text(
    'The dashboard (GET /dashboard) serves as the patient\'s command center. It displays all '
    'scheduled appointments in a tabular format showing the doctor\'s name, date, time slot, '
    'reason for visit, uploaded documents, and status badge. An empty state with a call-to-action '
    'button is shown when no appointments exist.'
)
pdf.body_text(
    'The integrated doctor search uses a GET form with query parameter "search" that performs '
    'a SQL LIKE query against doctor names and email addresses. Results are displayed with a '
    '"Book Slot" button that links to the booking page with the doctor pre-selected. Search '
    'inputs are sanitized through the security.sanitize_text() function to prevent injection.'
)

pdf.sub_title('4.3 Appointment Booking with Document Upload')
pdf.body_text(
    'The booking page (GET/POST /book) implements a multi-step form:'
)
pdf.bullet('Doctor Selection: Dropdown populated from the users table (role = doctor)')
pdf.bullet('Date Picker: HTML5 date input restricted to weekdays (Mon-Fri) and future dates')
pdf.bullet('Time Slot Grid: Dynamic 12-slot grid (30-min intervals, 9 AM - 12 PM and 2 PM - '
           '4:30 PM). Booked slots are fetched via a REST API call to /api/appointments and '
           'displayed as disabled with strikethrough styling.')
pdf.bullet('Reason Textarea: 500-character limit with real-time counter')
pdf.bullet('Document Upload: Drag-and-drop zone accepting PDF, JPG, JPEG, PNG (max 2MB). '
           'Client-side extension and size checks precede server-side validation.')
pdf.body_text(
    'The server-side booking logic performs: date validation (no past dates, weekdays only), '
    'time slot validation against a whitelist, file upload validation (extension, size, magic '
    'byte signature), and a double-booking check query against the database UNIQUE constraint.'
)

pdf.sub_title('4.4 Doctor Schedule Management')
pdf.body_text(
    'The doctor schedule view (GET /doctor/schedule) presents a daily agenda with a date filter '
    'that auto-submits on change. The table displays: time slot (accent-colored), patient name, '
    'contact phone, reason for visit (styled with a left accent border), and medical document '
    'download links. An empty state with a calendar icon placeholder appears when no '
    'consultations are scheduled for the selected date.'
)

pdf.sub_title('4.5 Appointment Cancellation')
pdf.body_text(
    'Patients can cancel appointments via POST /cancel/<appointment_id>. The route validates '
    'that the current user owns the appointment before executing the DELETE. A JavaScript '
    'confirmation dialog prevents accidental cancellations. The corresponding REST API endpoint '
    '(DELETE /api/appointments/<id>) provides the same functionality for programmatic clients.'
)
pdf.add_page()

# --- 5. SECURITY ---
pdf.section_title('5. Security Architecture')

pdf.sub_title('5.1 Password Security & Strength Enforcement')
pdf.bullet('bcrypt hashing with 12 salt rounds (industry standard)')
pdf.bullet('5-criteria strength validation: 8+ chars, upper, lower, digit, special character')
pdf.bullet('Real-time visual strength meter with color-coded bar (red/amber/green)')
pdf.bullet('Checklist UI showing which criteria are met in real-time')

pdf.sub_title('5.2 CSRF Protection')
pdf.body_text(
    'Flask-WTF CSRFProtect is enabled globally. Every form includes a hidden csrf_token field '
    'generated by the server. API endpoints are exempted from CSRF because they use token-based '
    'authentication (JWT Bearer tokens). A custom CSRF error handler catches validation failures '
    'and redirects users with a friendly message.'
)

pdf.sub_title('5.3 Input Sanitization (XSS Prevention)')
pdf.body_text(
    'All user-supplied text (search queries, appointment reasons) is processed through '
    'security.sanitize_text(), which uses the Bleach library to strip all HTML tags. This '
    'prevents stored and reflected XSS attacks. The sanitization function allows zero HTML '
    'tags and zero attributes, effectively rendering any injected markup as plain text.'
)

pdf.sub_title('5.4 Rate Limiting & Brute-Force Protection')
pdf.body_text(
    'The check_rate_limit function queries the login_attempts table to count failed attempts '
    'from a given IP address within a 15-minute window. If the count exceeds 5 failures, the '
    'login is blocked with a user-facing message. The function uses Python-computed timestamps '
    '(database-agnostic) rather than database-specific date functions, ensuring compatibility '
    'across SQLite and PostgreSQL.'
)

pdf.sub_title('5.5 Session Management & Inactivity Timeout')
pdf.bullet('Session permanent lifetime set to 15 minutes')
pdf.bullet('Every request updates a last_activity timestamp in the session')
pdf.bullet('Stale sessions (older than 15 min) trigger automatic logout with redirect to login')
pdf.bullet('Client-side inactivity watchdog: JavaScript timer warns at 14 minutes, forces '
           'logout at 15 minutes with a fixed-position warning banner')
pdf.bullet('Session fixation prevention: session.clear() before populating new session on login')
pdf.bullet('Secure cookie flags: HttpOnly=True, SameSite=Lax, Secure=True in production')

pdf.sub_title('5.6 JWT-Based API Authentication')
pdf.body_text(
    'The REST API supports dual authentication: JWT Bearer tokens (preferred) and session '
    'cookies (fallback). The get_authenticated_user() function checks the Authorization header '
    'for a Bearer token, decodes it using PyJWT with HS256 algorithm, and extracts the user ID '
    'and role. Tokens expire after 2 hours. Invalid or expired tokens return 401 Unauthorized. '
    'The JWT secret is generated using Python\'s secrets.token_hex(32) if not set via environment '
    'variable, ensuring each deployment gets a unique, cryptographically strong key.'
)

pdf.sub_title('5.7 File Upload Security (Magic Byte Validation)')
pdf.body_text(
    'File uploads undergo a comprehensive 3-layer validation:'
)
pdf.bullet('Extension check: Only .pdf, .jpg, .jpeg, .png are allowed')
pdf.bullet('Size check: Files are limited to 2MB (MAX_CONTENT_LENGTH)')
pdf.bullet('Magic byte signature check: The first 16 bytes of each file are read and compared '
           'against known file signatures (%PDF, \\xFF\\xD8\\xFF for JPEG, \\x89PNG for PNG). '
           'This prevents MIME type spoofing attacks.')
pdf.body_text(
    'Files are saved with a timestamp-prefixed secure filename (via Werkzeug\'s secure_filename) '
    'to the uploads/ directory, preventing path traversal attacks.'
)

pdf.sub_title('5.8 Access Control & Authorization')
pdf.bullet('Role-based route protection: Patient routes check session["role"] == "patient", '
           'doctor routes check session["role"] == "doctor"')
pdf.bullet('Document access control: The view_document endpoint verifies the requesting user is '
           'either the patient who uploaded the document or the assigned doctor')
pdf.bullet('API endpoints validate JWT/subject against requested resources')
pdf.bullet('Cancellation endpoint verifies appointment ownership before executing DELETE')
pdf.add_page()

# --- 6. REST API ---
pdf.section_title('6. REST API Design')
pdf.body_text(
    'The application exposes 5 JSON API endpoints for programmatic access:')

pdf.sub_title('POST /api/token  -  Obtain JWT Token')
pdf.code_block(
    '  Request:  {"email": "...", "password": "...", "role": "patient"}\n'
    '  Response: {"token": "<jwt>", "expires_in_hours": 2}'
)
pdf.body_text('Authenticates a user and returns a signed JWT token valid for 2 hours.')

pdf.sub_title('GET /api/appointments  -  List Appointments')
pdf.code_block(
    '  Params: doctor_id, date  (optional - checks slot availability)\n'
    '  Response: {"appointments": [{"time_slot": "10:00 AM"}, ...]}'
)
pdf.body_text(
    'When called with doctor_id and date parameters, returns booked time slots for availability '
    'checking. When called with valid authentication, returns the authenticated patient\'s bookings.')

pdf.sub_title('POST /api/appointments/book  -  Book Appointment')
pdf.code_block(
    '  Request:  {"doctor_id": 1, "date": "2026-06-15",\n'
    '             "time_slot": "10:00 AM", "reason": "Checkup"}\n'
    '  Response: {"success": true, "message": "Appointment booked successfully"}'
)

pdf.sub_title('GET /api/doctor/schedule  -  Doctor Schedule')
pdf.code_block(
    '  Params: date (YYYY-MM-DD)\n'
    '  Response: {"date": "2026-06-15",\n'
    '             "schedule": [{"id": 1, "time_slot": "09:00 AM",\n'
    '                           "patient": "John Doe", ...}]}'
)
pdf.body_text('Returns a doctor\'s scheduled consultations for a specific date.')

pdf.sub_title('DELETE /api/appointments/<id>  -  Cancel Appointment')
pdf.code_block(
    '  Response: {"success": true, "message": "Appointment cancelled"}'
)
pdf.body_text('Cancels an appointment. Requires patient authentication and appointment ownership.')
pdf.ln(4)

# --- 7. FRONTEND ---
pdf.section_title('7. Frontend Design & UX')
pdf.body_text(
    'The frontend is built with semantic HTML5, custom CSS3, and vanilla JavaScript. No external '
    'CSS or JS frameworks are used, minimizing dependency bloat and potential supply chain risks.'
)
pdf.bullet('Dark theme with CSS custom properties (--bg-main: #0a0d1a) and gradient backgrounds')
pdf.bullet('Glassmorphism card design using backdrop-filter: blur(16px) for a modern aesthetic')
pdf.bullet('Outfit/Inter font family via Google Fonts for clean, professional typography')
pdf.bullet('Responsive grid layout: 2-column dashboard (2fr + 1fr) collapsing to single column '
           'on mobile (768px breakpoint)')
pdf.bullet('Interactive elements: password strength meter, tab switcher for login roles, drag-and-drop '
           'file upload zone, AJAX slot availability fetching')
pdf.bullet('Inline SVG icons throughout for visual affordance (calendar, search, upload, user icons)')
pdf.bullet('Status badges (scheduled/completed) with semi-transparent colored backgrounds')
pdf.bullet('Gradient buttons with hover animations (translateY + box-shadow transitions)')
pdf.ln(4)

# --- 8. DEPLOYMENT ---
pdf.section_title('8. Deployment on Render')
pdf.body_text(
    'The application is deployed on Render.com using the Blueprint infrastructure-as-code approach. '
    'The render.yaml file at the repository root defines the full deployment specification:'
)
pdf.bullet('Web Service: Python 3 environment, Oregon region, Free tier plan')
pdf.bullet('Build Command: pip install -r requirements.txt')
pdf.bullet('Start Command: gunicorn app:app (production WSGI server)')
pdf.bullet('Auto-scaling: Gunicorn worker processes managed by Render')
pdf.bullet('Environment Variables: SECRET_KEY and JWT_SECRET auto-generated with secure random '
           'values via generateValue: true in render.yaml')
pdf.bullet('PostgreSQL: Automatically provisioned with DATABASE_URL injected into the environment')
pdf.bullet('Auto-deploy: Connected to GitHub repository; Render automatically redeploys on every '
           'git push to the main branch')
pdf.body_text(
    'The database module detects the DATABASE_URL environment variable and automatically switches '
    'from SQLite to PostgreSQL, applying the necessary placeholder conversions transparently. '
    'Session cookies are automatically configured as Secure=True in production (detected by '
    'FLASK_DEBUG=0), ensuring compliance with HTTPS requirements.'
)
pdf.ln(4)

# --- 9. TECH ---
pdf.section_title('9. Technologies & Dependencies')
pdf.body_text('Core Framework & Libraries:')
pdf.bullet('Flask 3.x - Python web micro-framework for routing, templating, and session management')
pdf.bullet('Flask-WTF - CSRF protection integration with form validation')
pdf.bullet('Jinja2 (bundled with Flask) - Server-side HTML template rendering')
pdf.bullet('Bleach 6.x - HTML sanitization library for XSS prevention')
pdf.bullet('bcrypt 5.x - Password hashing with 12-round salt generation')
pdf.bullet('PyJWT 2.x - JSON Web Token encoding and decoding (HS256)')
pdf.bullet('python-dotenv - Environment variable loading from .env files')
pdf.bullet('psycopg2-binary - PostgreSQL adapter for Python')
pdf.bullet('Gunicorn - Production-grade WSGI HTTP server')
pdf.body_text('Database:')
pdf.bullet('SQLite 3 (local development) - File-based relational database')
pdf.bullet('PostgreSQL (production on Render) - Managed cloud database')
pdf.body_text('Frontend:')
pdf.bullet('HTML5, CSS3, vanilla JavaScript (no frameworks)')
pdf.bullet('Google Fonts: Inter (body), Outfit (headings)')
pdf.ln(4)

# --- 10. CONCLUSION ---
pdf.section_title('10. Conclusion')
pdf.body_text(
    'The Doctor Appointment System successfully delivers a secure, production-ready medical '
    'booking platform with the following key achievements:'
)
pdf.bullet('Complete dual-role workflow: Patients browse doctors, book appointments, upload '
           'documents, and cancel bookings. Doctors view daily schedules with patient details '
           'and clinical documents.')
pdf.bullet('Defense-in-depth security: Multiple overlapping security layers including bcrypt '
           'hashing, CSRF tokens, XSS sanitization, rate limiting, JWT authentication, magic '
           'byte file validation, session timeout, and strict role-based access control.')
pdf.bullet('Database abstraction layer: The DbConnection/DbCursor wrappers provide transparent '
           'SQLite-to-PostgreSQL migration, enabling seamless local development and cloud deployment '
           'from a single codebase.')
pdf.bullet('REST API: 5 JSON endpoints with JWT Bearer authentication enable external client '
           'integration (mobile apps, third-party systems).')
pdf.bullet('Cloud-ready deployment: render.yaml Blueprint spec enables one-click deployment '
           'on Render with auto-provisioned PostgreSQL, auto-generated secrets, and continuous '
           'deployment from GitHub.')
pdf.body_text(
    'All 5 security unit tests pass successfully (password strength, XSS sanitization, rate '
    'limiting, JWT token generation/validation, and API endpoint protection). The codebase '
    'follows industry best practices for web security, database design, and cloud deployment.'
)
pdf.ln(6)
pdf.set_font('Helvetica', 'I', 9)
pdf.set_text_color(128, 128, 128)
pdf.cell(0, 5, '--- End of Report ---', new_x='LMARGIN', new_y='NEXT', align='C')
pdf.cell(0, 5, 'Doctor Appointment System - Technical Report', new_x='LMARGIN', new_y='NEXT', align='C')
pdf.cell(0, 5, f'Generated on {datetime.now().strftime("%B %d, %Y at %H:%M")}', new_x='LMARGIN', new_y='NEXT', align='C')

# --- OUTPUT ---
output_path = 'Doctor_Appointment_System_Report.pdf'
pdf.output(output_path)
print(f'Report generated: {output_path}')
