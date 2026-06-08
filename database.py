import os
import sqlite3
import bcrypt

DATABASE_URL = os.environ.get('DATABASE_URL')
PGSQL_URL = None

if DATABASE_URL:
    if 'sslmode=' not in DATABASE_URL:
        if '?' in DATABASE_URL:
            PGSQL_URL = DATABASE_URL + '&sslmode=require'
        else:
            PGSQL_URL = DATABASE_URL + '?sslmode=require'
    else:
        PGSQL_URL = DATABASE_URL

USE_POSTGRES = False
psycopg2 = None
psycopg2_extras = None

if DATABASE_URL:
    try:
        import psycopg2
        import psycopg2.extras
        USE_POSTGRES = True
        print(f"Using PostgreSQL: {DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else 'connected'}")
    except ImportError:
        print("psycopg2 not installed, falling back to SQLite")

DB_PATH = os.path.join(os.path.dirname(__file__), 'db.sqlite')


class DbCursor:
    def __init__(self, pg_cursor=None, sqlite_cursor=None):
        self._pg = pg_cursor
        self._sq = sqlite_cursor
        self.description = None

    def _convert_query(self, query):
        if USE_POSTGRES:
            return query.replace('?', '%s')
        return query

    def execute(self, query, params=None):
        query = self._convert_query(query)
        if USE_POSTGRES:
            self._pg.execute(query, params or ())
            self.description = self._pg.description
        else:
            self._sq.execute(query, params or ())
            self.description = self._sq.description

    def fetchone(self):
        if USE_POSTGRES:
            row = self._pg.fetchone()
            if row:
                colnames = [desc[0] for desc in (self.description or [])]
                return DbRow(dict(zip(colnames, row)))
            return None
        else:
            row = self._sq.fetchone()
            if row is not None:
                return DbRow(dict(row))
            return None

    def fetchall(self):
        if USE_POSTGRES:
            rows = self._pg.fetchall()
            colnames = [desc[0] for desc in (self.description or [])]
            return [DbRow(dict(zip(colnames, row))) for row in rows]
        else:
            return [DbRow(dict(row)) for row in self._sq.fetchall()]

    def close(self):
        pass


class DbRow(dict):
    pass


class DbConnection:
    def __init__(self, conn):
        self._conn = conn
        self._cursor = None

    def cursor(self):
        if USE_POSTGRES:
            self._cursor = DbCursor(pg_cursor=self._conn.cursor())
        else:
            self._cursor = DbCursor(sqlite_cursor=self._conn.cursor())
        return self._cursor

    def commit(self):
        self._conn.commit()

    def close(self):
        if self._cursor:
            self._cursor.close()
        self._conn.close()


def get_db_connection():
    if USE_POSTGRES:
        try:
            conn = psycopg2.connect(PGSQL_URL)
            return DbConnection(conn)
        except Exception as e:
            print(f"PostgreSQL connection failed: {e}, falling back to SQLite")
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            return DbConnection(conn)
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return DbConnection(conn)


def init_db():
    conn = None
    try:
        if USE_POSTGRES:
            conn = psycopg2.connect(PGSQL_URL)
            conn = DbConnection(conn)
        else:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            conn = DbConnection(conn)
    except Exception as e:
        print(f"Database init connection failed: {e}")
        return

    cursor = conn.cursor()

    if USE_POSTGRES:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('patient', 'doctor', 'admin')),
            totp_secret TEXT,
            totp_enabled INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            id SERIAL PRIMARY KEY,
            patient_id INTEGER NOT NULL REFERENCES users(id),
            doctor_id INTEGER NOT NULL REFERENCES users(id),
            date TEXT NOT NULL,
            time_slot TEXT NOT NULL,
            reason TEXT NOT NULL,
            document_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(doctor_id, date, time_slot)
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success INTEGER NOT NULL CHECK(success IN (0, 1))
        );
        """)
    else:
        cursor.execute("PRAGMA foreign_keys = ON;")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('patient', 'doctor', 'admin')),
            totp_secret TEXT,
            totp_enabled INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            doctor_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            time_slot TEXT NOT NULL,
            reason TEXT NOT NULL,
            document_path TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patient_id) REFERENCES users(id),
            FOREIGN KEY (doctor_id) REFERENCES users(id),
            UNIQUE(doctor_id, date, time_slot)
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            success INTEGER NOT NULL CHECK(success IN (0, 1))
        );
        """)

    conn.commit()

    # Migrate role constraint for PostgreSQL
    if USE_POSTGRES:
        try:
            cursor.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;")
            cursor.execute("ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('patient', 'doctor', 'admin'));")
            conn.commit()
        except Exception:
            pass

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT;")
            conn.commit()
        except Exception:
            pass

        try:
            cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled INTEGER DEFAULT 0;")
            conn.commit()
        except Exception:
            pass
    else:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT;")
            conn.commit()
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0;")
            conn.commit()
        except Exception:
            pass

    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'doctor';")
    row = cursor.fetchone()
    doctor_count = list(row.values())[0] if row else 0

    if doctor_count == 0:
        seed_doctors(cursor)
        conn.commit()

    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin';")
    row = cursor.fetchone()
    admin_count = list(row.values())[0] if row else 0

    if admin_count == 0:
        seed_admin(cursor)
        conn.commit()

    conn.close()
    print("Database initialised successfully.")


def seed_doctors(cursor):
    password = b"SecurePassword123!"
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password, salt).decode('utf-8')

    doctors = [
        ("Dr. Alice Smith (Cardiology)", "alice.smith@hospital.com", "+1-555-0199", hashed),
        ("Dr. Bob Jones (Pediatrics)", "bob.jones@hospital.com", "+1-555-0188", hashed),
        ("Dr. Carol White (Dermatology)", "carol.white@hospital.com", "+1-555-0177", hashed),
        ("Dr. David Evans (General Medicine)", "david.evans@hospital.com", "+1-555-0166", hashed)
    ]

    for name, email, phone, pwd_hash in doctors:
        cursor.execute("""
        INSERT INTO users (name, email, phone, password_hash, role)
        VALUES (?, ?, ?, ?, 'doctor');
        """, (name, email, phone, pwd_hash))

    print("Doctors seeded successfully.")


def seed_admin(cursor):
    password = b"AdminPass123!"
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password, salt).decode('utf-8')

    cursor.execute("""
    INSERT INTO users (name, email, phone, password_hash, role)
    VALUES (?, ?, ?, ?, 'admin');
    """, ("System Administrator", "admin@medsecure.com", "+1-555-0000", hashed))

    print("Admin account seeded successfully.")


if __name__ == '__main__':
    init_db()
