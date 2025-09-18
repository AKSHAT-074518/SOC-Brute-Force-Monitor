import datetime
import random
import json
import csv
import os

class BruteForceDetector:
    def __init__(self):
        self.failed_attempts = {}
        self.threshold = 5  # 5 failed attempts = brute force
        self.locked_accounts = set()
        self.login_history = []
        
        # Valid credentials for testing
        self.valid_credentials = {
            "admin": "password123",
            "user1": "welcome", 
            "john": "secure123",
            "test": "test123",
            "demo": "demo123"
        }
        
        print("✅ BruteForceDetector initialized")
        print(f"📊 Threshold set to: {self.threshold} failed attempts")
    
    def generate_fake_ip(self):
        """Generate random IP address for simulation"""
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    
    def simulate_login(self, username, password):
        """Main login simulation function"""
        ip_address = self.generate_fake_ip()
        timestamp = datetime.datetime.now()
        
        print(f"🔍 Login attempt: {username} from {ip_address}")
        
        # Check if account is locked
        if username in self.locked_accounts:
            status = "LOCKED"
            print(f"🔒 Account {username} is locked!")
        elif username in self.valid_credentials and password == self.valid_credentials[username]:
            status = "SUCCESS"
            self.reset_failed_attempts(username)
            print(f"✅ Login successful for {username}")
        else:
            status = "FAILED"
            brute_force_detected = self.track_failed_attempt(username, ip_address)
            if brute_force_detected:
                print(f"🚨 BRUTE FORCE DETECTED for {username}!")
            print(f"❌ Login failed for {username}")
            
        self.log_attempt(timestamp, username, status, ip_address)
        return status, ip_address
    
    def track_failed_attempt(self, username, ip_address):
        """Track failed login attempts"""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = []
        
        self.failed_attempts[username].append({
            'timestamp': datetime.datetime.now(),
            'ip_address': ip_address
        })
        
        failed_count = len(self.failed_attempts[username])
        print(f"📈 Failed attempts for {username}: {failed_count}/{self.threshold}")
        
        # Check if threshold exceeded
        if failed_count >= self.threshold:
            self.lock_account(username)
            return True  # Brute force detected
        return False
    
    def lock_account(self, username):
        """Lock account due to brute force"""
        self.locked_accounts.add(username)
        print(f"🔒 Account {username} has been LOCKED!")
    
    def reset_failed_attempts(self, username):
        """Reset failed attempts on successful login"""
        if username in self.failed_attempts:
            del self.failed_attempts[username]
            print(f"🔄 Reset failed attempts for {username}")
    
    def log_attempt(self, timestamp, username, status, ip_address):
        """Log all login attempts"""
        log_entry = {
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'username': username,
            'status': status,
            'ip_address': ip_address
        }
        
        self.login_history.append(log_entry)
        
        # Save to CSV file
        try:
            file_exists = os.path.isfile('login_attempts.csv')
            with open('login_attempts.csv', 'a', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['timestamp', 'username', 'status', 'ip_address']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                # Write header if file is new
                if not file_exists:
                    writer.writeheader()
                    print("📝 Created new CSV log file")
                
                writer.writerow(log_entry)
        except Exception as e:
            print(f"❌ CSV logging error: {e}")
    
    def get_failed_attempts_summary(self):
        """Get summary of failed attempts"""
        summary = {}
        for username, attempts in self.failed_attempts.items():
            summary[username] = {
                'count': len(attempts),
                'last_attempt': attempts[-1]['timestamp'] if attempts else None,
                'is_locked': username in self.locked_accounts
            }
        return summary