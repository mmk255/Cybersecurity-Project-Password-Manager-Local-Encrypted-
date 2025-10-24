import os
import json
import base64
import secrets
import string
import hashlib
import getpass
import pyperclip
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManager:
    def __init__(self, data_file='passwords.enc'):
        self.data_file = data_file
        self.master_hash_file = 'master.hash'
        self.salt_file = 'salt.key'
        self.fernet = None
        self.passwords = {}
        
    def _derive_key(self, master_password, salt):
        """Derive encryption key from master password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key
    
    def _hash_master_password(self, password):
        """Hash master password for verification (not for encryption)"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def setup_master_password(self):
        """Initial setup - create master password"""
        print("\n=== Password Manager Setup ===")
        print("Create a strong master password. This will be used to encrypt all your passwords.")
        
        while True:
            master = getpass.getpass("Enter master password: ")
            confirm = getpass.getpass("Confirm master password: ")
            
            if master != confirm:
                print(" Passwords don't match. Try again.")
                continue
            
            strength = self._check_password_strength(master)
            if strength < 3:
                print("  Weak master password. Please use a stronger one.")
                print("   Tips: Use 12+ characters, mix uppercase, lowercase, numbers, and symbols")
                continue
            
            break
        
        # Generate salt and save it
        salt = os.urandom(16)
        with open(self.salt_file, 'wb') as f:
            f.write(salt)
        
        # Hash master password for verification
        master_hash = self._hash_master_password(master)
        with open(self.master_hash_file, 'w') as f:
            f.write(master_hash)
        
        # Derive encryption key
        key = self._derive_key(master, salt)
        self.fernet = Fernet(key)
        
        # Create empty password store
        self.passwords = {}
        self._save_passwords()
        
        print(" Master password set successfully!")
        return True
    
    def authenticate(self):
        """Authenticate with master password"""
        if not os.path.exists(self.master_hash_file):
            return self.setup_master_password()
        
        # Load salt
        with open(self.salt_file, 'rb') as f:
            salt = f.read()
        
        # Load master password hash
        with open(self.master_hash_file, 'r') as f:
            stored_hash = f.read()
        
        attempts = 3
        while attempts > 0:
            master = getpass.getpass("\nEnter master password: ")
            
            if self._hash_master_password(master) == stored_hash:
                # Derive encryption key
                key = self._derive_key(master, salt)
                self.fernet = Fernet(key)
                
                # Load passwords
                self._load_passwords()
                print(" Authentication successful!")
                return True
            else:
                attempts -= 1
                if attempts > 0:
                    print(f" Incorrect password. {attempts} attempts remaining.")
                else:
                    print(" Authentication failed. Exiting.")
                    return False
        
        return False
    
    def _load_passwords(self):
        """Load and decrypt passwords from file"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.fernet.decrypt(encrypted_data)
                self.passwords = json.loads(decrypted_data.decode())
            except Exception as e:
                print(f"  Error loading passwords: {e}")
                self.passwords = {}
        else:
            self.passwords = {}
    
    def _save_passwords(self):
        """Encrypt and save passwords to file"""
        data = json.dumps(self.passwords, indent=2)
        encrypted_data = self.fernet.encrypt(data.encode())
        with open(self.data_file, 'wb') as f:
            f.write(encrypted_data)
    
    def _check_password_strength(self, password):
        """Check password strength (0-5 scale)"""
        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in string.punctuation for c in password):
            score += 1
        return min(score, 5)
    
    def generate_password(self, length=16, use_symbols=True):
        """Generate a strong random password"""
        chars = string.ascii_letters + string.digits
        if use_symbols:
            chars += string.punctuation
        
        # Ensure at least one of each type
        password = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
        ]
        if use_symbols:
            password.append(secrets.choice(string.punctuation))
        
        # Fill the rest randomly
        password += [secrets.choice(chars) for _ in range(length - len(password))]
        
        # Shuffle
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)
    
    def add_password(self, service, username, password=None, notes=""):
        """Add a new password entry"""
        if service in self.passwords:
            overwrite = input(f"  Entry for '{service}' already exists. Overwrite? (y/n): ")
            if overwrite.lower() != 'y':
                print("❌ Cancelled.")
                return
        
        if password is None:
            gen = input("Generate password? (y/n): ")
            if gen.lower() == 'y':
                length = input("Password length (default 16): ").strip()
                length = int(length) if length else 16
                symbols = input("Include symbols? (y/n): ").lower() == 'y'
                password = self.generate_password(length, symbols)
                print(f" Generated password: {password}")
            else:
                password = getpass.getpass("Enter password: ")
        
        self.passwords[service] = {
            'username': username,
            'password': password,
            'notes': notes,
            'strength': self._check_password_strength(password)
        }
        
        self._save_passwords()
        print(f" Password for '{service}' saved successfully!")
    
    def get_password(self, service):
        """Retrieve a password"""
        if service not in self.passwords:
            print(f" No entry found for '{service}'")
            return
        
        entry = self.passwords[service]
        print(f"\n📋 Entry for: {service}")
        print(f"   Username: {entry['username']}")
        print(f"   Password: {entry['password']}")
        if entry['notes']:
            print(f"   Notes: {entry['notes']}")
        print(f"   Strength: {'⭐' * entry['strength']}")
        
        copy = input("\nCopy password to clipboard? (y/n): ")
        if copy.lower() == 'y':
            pyperclip.copy(entry['password'])
            print(" Password copied to clipboard!")
    
    def list_services(self):
        """List all stored services"""
        if not self.passwords:
            print("📭 No passwords stored yet.")
            return
        
        print(f"\n Stored passwords ({len(self.passwords)}):")
        print("-" * 60)
        for service, entry in sorted(self.passwords.items()):
            strength_stars = '⭐' * entry['strength']
            print(f"  • {service:<30} | {entry['username']:<20} | {strength_stars}")
    
    def delete_password(self, service):
        """Delete a password entry"""
        if service not in self.passwords:
            print(f"❌ No entry found for '{service}'")
            return
        
        confirm = input(f"  Delete password for '{service}'? (y/n): ")
        if confirm.lower() == 'y':
            del self.passwords[service]
            self._save_passwords()
            print(f" Password for '{service}' deleted.")
        else:
            print("❌ Cancelled.")
    
    def audit_passwords(self):
        """Audit all passwords for strength"""
        if not self.passwords:
            print("📭 No passwords to audit.")
            return
        
        weak = []
        moderate = []
        strong = []
        
        for service, entry in self.passwords.items():
            strength = entry['strength']
            if strength <= 2:
                weak.append(service)
            elif strength <= 3:
                moderate.append(service)
            else:
                strong.append(service)
        
        print("\n🔍 Password Strength Audit")
        print("-" * 60)
        print(f" Strong passwords ({len(strong)}): {', '.join(strong) if strong else 'None'}")
        print(f"  Moderate passwords ({len(moderate)}): {', '.join(moderate) if moderate else 'None'}")
        print(f" Weak passwords ({len(weak)}): {', '.join(weak) if weak else 'None'}")
        
        if weak:
            print("\n Recommendation: Update weak passwords immediately!")

def main():
    pm = PasswordManager()
    
    print("=" * 60)
    print("🔐 SECURE PASSWORD MANAGER")
    print("=" * 60)
    
    if not pm.authenticate():
        return
    
    while True:
        print("\n" + "=" * 60)
        print("MENU:")
        print("  1. Add password")
        print("  2. Get password")
        print("  3. List all services")
        print("  4. Delete password")
        print("  5. Generate password")
        print("  6. Audit password strength")
        print("  7. Exit")
        print("=" * 60)
        
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            service = input("Service name (e.g., Gmail, GitHub): ").strip()
            username = input("Username/Email: ").strip()
            notes = input("Notes (optional): ").strip()
            pm.add_password(service, username, notes=notes)
        
        elif choice == '2':
            service = input("Service name: ").strip()
            pm.get_password(service)
        
        elif choice == '3':
            pm.list_services()
        
        elif choice == '4':
            service = input("Service name: ").strip()
            pm.delete_password(service)
        
        elif choice == '5':
            length = input("Password length (default 16): ").strip()
            length = int(length) if length else 16
            symbols = input("Include symbols? (y/n): ").lower() == 'y'
            password = pm.generate_password(length, symbols)
            print(f"\n Generated password: {password}")
            copy = input("Copy to clipboard? (y/n): ")
            if copy.lower() == 'y':
                pyperclip.copy(password)
                print(" Copied!")
        
        elif choice == '6':
            pm.audit_passwords()
        
        elif choice == '7':
            print("\n👋 Goodbye! Your passwords are secure.")
            break
        
        else:
            print(" Invalid option. Please try again.")

if __name__ == "__main__":

    main()
