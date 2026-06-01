import unittest
import os
import sqlite3
import jwt
from datetime import datetime, timedelta

import security
import database
from app import app

class TestSecurityFeatures(unittest.TestCase):
    
    def setUp(self):
        # Setup testing config for Flask test client
        self.app = app.test_client()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for simplified test requests
        
        # Setup temporary SQLite database for rate limiter testing
        self.db_path = 'test_db.sqlite'
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            success INTEGER NOT NULL CHECK(success IN (0, 1))
        );
        """)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    # 1. Test Password Strength Validator
    def test_password_strength_validator(self):
        # Under 8 characters
        self.assertFalse(security.is_password_strong("Sh1!")[0])
        # Missing lowercase
        self.assertFalse(security.is_password_strong("STRONG123!")[0])
        # Missing uppercase
        self.assertFalse(security.is_password_strong("weak12345!")[0])
        # Missing digits
        self.assertFalse(security.is_password_strong("WeakPassword!")[0])
        # Missing special character
        self.assertFalse(security.is_password_strong("WeakPassword123")[0])
        # Valid strong password
        self.assertTrue(security.is_password_strong("StrongPass123!")[0])

    # 2. Test Input Sanitization (Bleach XSS protection)
    def test_xss_sanitization(self):
        dirty_html = "<script>alert('XSS')</script>Persistent Cough"
        clean = security.sanitize_text(dirty_html)
        self.assertNotIn("<script>", clean)
        self.assertNotIn("</script>", clean)
        
        dirty_nested = "<img src=x onerror=alert(1)>Chest pains"
        clean_nested = security.sanitize_text(dirty_nested)
        self.assertNotIn("<img", clean_nested)
        self.assertNotIn("onerror", clean_nested)
        
        plain_text = "Severe fever and body chills."
        clean_plain = security.sanitize_text(plain_text)
        self.assertEqual(clean_plain, plain_text)

    # 3. Test Database Rate Limiter
    def test_rate_limiter(self):
        ip = "192.168.1.100"
        
        # Test under threshold (limit is 3 for test)
        for i in range(2):
            security.log_login_attempt(self.conn, "test@test.com", ip, success=False)
            
        allowed = security.check_rate_limit(self.conn, ip, 'login', limit=3, period_seconds=60)
        self.assertTrue(allowed)
        
        # Add 3rd failed attempt (should hit limit)
        security.log_login_attempt(self.conn, "test@test.com", ip, success=False)
        allowed = security.check_rate_limit(self.conn, ip, 'login', limit=3, period_seconds=60)
        self.assertFalse(allowed)

    # 4. Test JWT Helpers
    def test_jwt_tokens(self):
        user_id = 42
        role = "patient"
        
        # Generate token
        token = security.generate_jwt_token(user_id, role)
        self.assertIsNotNone(token)
        
        # Decode valid token
        payload = security.decode_jwt_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload['sub'], str(user_id))
        self.assertEqual(payload['role'], role)
        
        # Verify forged signature fails
        forged_token = token[:-5] + "aaaaa"
        payload_forged = security.decode_jwt_token(forged_token)
        self.assertIsNone(payload_forged)

    # 5. Test API Security (Part E)
    def test_api_endpoints_protection(self):
        # Request without credentials/JWT to protected endpoints
        res1 = self.app.get('/api/appointments')
        self.assertEqual(res1.status_code, 401)
        self.assertIn("error", res1.get_json())

        res2 = self.app.get('/api/doctor/schedule')
        self.assertEqual(res2.status_code, 401)
        self.assertIn("error", res2.get_json())

        res3 = self.app.post('/api/appointments/book', json={
            "doctor_id": 1,
            "date": "2026-06-01",
            "time_slot": "10:00 AM",
            "reason": "Routine Checkup"
        })
        self.assertEqual(res3.status_code, 401)
        self.assertIn("error", res3.get_json())


if __name__ == '__main__':
    unittest.main()
