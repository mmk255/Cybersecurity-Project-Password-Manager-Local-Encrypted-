# 🔐 Secure Password Manager

A locally-encrypted password manager built with Python, implementing industry-standard cryptographic practices.

## Features

- **AES-256 Encryption** using Fernet symmetric encryption
- **PBKDF2 Key Derivation** with 480,000 iterations
- **Salted Key Storage** to prevent rainbow table attacks
- **Password Strength Analyzer** with visual feedback
- **Secure Password Generator** with customizable complexity
- **Password Audit Tool** to identify weak credentials
- **Clipboard Integration** for convenient password copying

## Security Implementation

- Master password is hashed with SHA-256 (never stored in plaintext)
- Encryption keys derived using PBKDF2HMAC with random salt
- All passwords encrypted at rest using AES-256
- Zero-knowledge architecture: passwords only decrypted when needed

## Installation
```bash
# Clone repository
git clone https://github.com/yourusername/password-manager.git
cd password-manager

# Install dependencies
pip install -r requirements.txt

# Run the application
python password_manager.py
```

## Usage

1. **First Run:** Create a strong master password
2. **Add Passwords:** Store credentials with optional auto-generation
3. **Retrieve Passwords:** Access stored credentials securely
4. **Audit Security:** Review password strength across all accounts

## Technical Stack

- **Python 3.x**
- **cryptography library** - Fernet (AES-256) encryption
- **PBKDF2HMAC** - Key derivation function
- **pyperclip** - Clipboard operations

## Project Goals

This project was created to demonstrate:
- Understanding of cryptographic principles
- Secure coding practices
- Real-world application of encryption algorithms
- User-focused security design

## Limitations & Future Improvements

**Current Limitations:**
- Local storage only (no cloud sync)
- No master password recovery (by design for security)
- Vulnerable to keyloggers on compromised systems

**Planned Features:**
- [ ] Integration with Have I Been Pwned API
- [ ] Export/import functionality
- [ ] Password expiration reminders
- [ ] Multi-factor authentication simulation

## Security Note

⚠️ **This is an educational project.** For production use, consider established password managers like Bitwarden, 1Password, or KeePass.

## License

MIT License - Feel free to use for learning purposes



