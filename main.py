import sys
import os
import logging
import datetime
from pathlib import Path
import uuid
import bcrypt
import pyotp
import sqlite3
import json
import subprocess
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

APP_DIR = Path(__file__).parent
QUARANTINE_DIR = APP_DIR /"malware"
QUARANTINE_DIR.mkdir(exist_ok=True)


from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QFileDialog, QListWidget,
    QMessageBox, QCheckBox, QComboBox, QStackedWidget, QListWidgetItem,
    QDialog
)
from PyQt6.QtGui import QFont, QDragEnterEvent, QDropEvent
from PyQt6.QtCore import Qt, QMimeData, QUrl

# Define application directory and subdirectories
APP_DIR = Path(__file__).parent
VAULT_DIR = APP_DIR / "vault"
EXTRACTED_DIR = APP_DIR / "extracted"
DB_PATH = APP_DIR / "vault.db"
CONFIG_PATH = APP_DIR / "config.json"
SESSION_PATH = APP_DIR / "session.json"

# Ensure directories exist
VAULT_DIR.mkdir(exist_ok=True)
EXTRACTED_DIR.mkdir(exist_ok=True)
(APP_DIR / "temp").mkdir(exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] - %(message)s",
    handlers=[
        logging.FileHandler(APP_DIR / "vault.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("secure_vault")

# Simulate fetching TOTP secret from an online resource
def fetch_totp_secret_online():
    try:
        totp_secret = pyotp.random_base32()
        logger.info("Simulated fetching TOTP secret from online resource.")
        return totp_secret
    except Exception as e:
        logger.error(f"Failed to fetch TOTP secret online: {e}")
        return pyotp.random_base32()

# Database initialization
def init_database():
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    # Drop existing tables to ensure schema consistency
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS files")
    # Create users table with hashed_password, session_token, and session_expiry
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            totp_secret TEXT,
            session_token TEXT,
            session_expiry TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            original_name TEXT NOT NULL,
            encrypted_path TEXT NOT NULL,
            upload_date TEXT NOT NULL,
            auto_delete_date TEXT,
            user_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

# Configuration management
def load_config():
    if not CONFIG_PATH.exists():
        default_config = {
            "encryption_level": "AES-256",
            "auto_delete_days": 30,
            "require_mfa": False,
            "max_failed_attempts": 5,
            "session_timeout_minutes": 1440,  # 24 hours
            "clamav_path": os.path.join("clamav-1.4.2.win.x64", "clamscan.exe")
        }
        save_config(default_config)
        return default_config
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
        # Add clamav_path if it doesn't exist in the config
        if "clamav_path" not in config:
            config["clamav_path"] = os.path.join("clamav-1.4.2.win.x64", "clamscan.exe")
            save_config(config)
        return config

def save_config(config):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4)

# Session management
def save_session(user_id, username, session_token):
    session_data = {
        "user_id": user_id,
        "username": username,
        "session_token": session_token,
        "timestamp": datetime.datetime.now().isoformat()
    }
    with open(SESSION_PATH, "w") as f:
        json.dump(session_data, f, indent=4)
    logger.info(f"Saved session for user {username}.")

def load_session():
    if not SESSION_PATH.exists():
        return None
    try:
        with open(SESSION_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load session: {e}")
        return None

def clear_session():
    if SESSION_PATH.exists():
        os.remove(SESSION_PATH)
        logger.info("Cleared session data.")

# Encryption utilities
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,  # Expects salt to be bytes
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as f:
        data = f.read()
    encrypted_data = fernet.encrypt(data)
    encrypted_path = VAULT_DIR / f"{uuid.uuid4()}.encrypted"
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)
    return encrypted_path

def decrypt_file(encrypted_path, key, output_path=None):
    fernet = Fernet(key)
    with open(encrypted_path, "rb") as f:
        encrypted_data = f.read()
    data = fernet.decrypt(encrypted_data)
    if output_path is None:
        temp_dir = APP_DIR / "temp"
        temp_dir.mkdir(exist_ok=True)
        output_path = temp_dir / f"decrypted_{uuid.uuid4()}"
    with open(output_path, "wb") as f:
        f.write(data)
    return output_path

def secure_delete_file(file_path):
    if not file_path.exists():
        return
    file_size = file_path.stat().st_size
    for _ in range(3):
        with open(file_path, "wb") as f:
            f.write(os.urandom(file_size))
    os.remove(file_path)


def scan_with_clamscan(file_path):
    config = load_config()
    clamav_path = config.get("clamav_path", os.path.join("clamav-1.4.2.win.x64", "clamscan.exe"))

    try:
        # Check if ClamAV executable exists
        if not os.path.exists(clamav_path):
            logger.error(f"ClamAV executable not found at: {clamav_path}")
            QMessageBox.warning(None, "ClamAV Not Found", 
                               f"ClamAV executable not found at: {clamav_path}\n"
                               f"Please configure the correct path in the settings.")
            return True  # Allow file to be added even if ClamAV is not available

        # Run ClamAV scan
        result = subprocess.run([clamav_path, file_path], capture_output=True, text=True)
        output = result.stdout
        logger.info(f"ClamAV scan output:\n{output}")

        if "OK" in output:
            logger.info(f"File is clean: {file_path}")
            return True
        elif "FOUND" in output:
            logger.warning(f"Malware found in file: {file_path}")
            return False
        else:
            logger.warning(f"Unknown ClamAV scan result:\n{output}")
            # Show a warning but allow the file to be added
            QMessageBox.warning(None, "ClamAV Scan", 
                               f"Unknown scan result for file: {file_path}\n"
                               f"Proceed with caution.")
            return True

    except Exception as e:
        logger.error(f"ClamAV scan failed: {e}")
        QMessageBox.warning(None, "ClamAV Scan Failed", 
                           f"Error scanning file: {e}\n"
                           f"File will be added without scanning.")
        return True  # Allow file to be added even if scan fails


def move_to_quarantine(file_path):
    destination = QUARANTINE_DIR / Path(file_path).name
    try:
        os.replace(file_path, destination)
        logger.warning(f"Malicious file moved to quarantine: {destination}")
    except Exception as e:
        logger.error(f"Failed to move file to quarantine: {e}")


# Authentication Manager
class AuthManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.current_user = None
        self.encryption_key = None
        self.failed_attempts = 0
        self.config = load_config()

    def register_user(self, username, password):
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        user_id = str(uuid.uuid4())
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        totp_secret = fetch_totp_secret_online() if self.config["require_mfa"] else None
        session_token = str(uuid.uuid4())
        session_expiry = (datetime.datetime.now() + datetime.timedelta(minutes=self.config["session_timeout_minutes"])).isoformat()
        try:
            cursor.execute(
                "INSERT INTO users (id, username, hashed_password, totp_secret, session_token, session_expiry) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, username, hashed_password.decode('utf-8'), totp_secret, session_token, session_expiry)
            )
            conn.commit()
            logger.info(f"User {username} registered successfully.")
            # Save session after registration
            save_session(user_id, username, session_token)
            # Auto-login after registration
            self.current_user = {"id": user_id, "username": username}
            self.encryption_key = derive_key(password, hashed_password)  # Pass hashed_password as bytes
            return True, totp_secret
        except sqlite3.IntegrityError:
            logger.error(f"Username {username} already exists.")
            return False, None
        finally:
            conn.close()

    def login(self, username, password, totp_code=None):
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT id, hashed_password, totp_secret FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if not user:
            self.failed_attempts += 1
            logger.warning(f"Login failed for {username}: User not found.")
            return False
        user_id, stored_hash, totp_secret = user
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            if self.config["require_mfa"] and totp_secret:
                totp = pyotp.TOTP(totp_secret)
                if not totp.verify(totp_code):
                    self.failed_attempts += 1
                    logger.warning(f"Login failed for {username}: Invalid TOTP.")
                    return False
            # Generate new session token on successful login
            session_token = str(uuid.uuid4())
            session_expiry = (datetime.datetime.now() + datetime.timedelta(minutes=self.config["session_timeout_minutes"])).isoformat()
            cursor.execute(
                "UPDATE users SET session_token = ?, session_expiry = ? WHERE id = ?",
                (session_token, session_expiry, user_id)
            )
            conn.commit()
            self.current_user = {"id": user_id, "username": username}
            self.encryption_key = derive_key(password, stored_hash.encode('utf-8'))  # Encode stored_hash to bytes
            self.failed_attempts = 0
            logger.info(f"User {username} logged in successfully.")
            # Save session after login
            save_session(user_id, username, session_token)
            conn.close()
            return True
        self.failed_attempts += 1
        logger.warning(f"Login failed for {username}: Incorrect password.")
        conn.close()
        return False

    def auto_login(self):
        session_data = load_session()
        if not session_data:
            return False
        user_id = session_data.get("user_id")
        session_token = session_data.get("session_token")
        if not user_id or not session_token:
            return False
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, hashed_password, session_token, session_expiry FROM users WHERE id = ? AND session_token = ?",
            (user_id, session_token)
        )
        user = cursor.fetchone()
        if not user:
            conn.close()
            return False
        user_id, username, stored_hash, db_session_token, session_expiry = user
        # Check if session has expired
        expiry_time = datetime.datetime.fromisoformat(session_expiry)
        if datetime.datetime.now() > expiry_time:
            logger.info(f"Session for user {username} has expired.")
            conn.close()
            clear_session()
            return False
        # Session is valid, auto-login
        self.current_user = {"id": user_id, "username": username}
        self.encryption_key = derive_key("", stored_hash.encode('utf-8'))  # Encode stored_hash to bytes
        logger.info(f"User {username} auto-logged in successfully.")
        conn.close()
        return True

    def logout(self):
        if self.current_user:
            username = self.current_user["username"]
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET session_token = NULL, session_expiry = NULL WHERE id = ?", (self.current_user["id"],))
            conn.commit()
            conn.close()
            logger.info(f"User {username} logged out.")
            self.current_user = None
            self.encryption_key = None
            clear_session()

    def is_authenticated(self):
        return self.current_user is not None

# File Manager
class FileManager:
    def __init__(self, db_path, auth_manager):
        self.db_path = db_path
        self.auth_manager = auth_manager

    def add_file(self, file_path, auto_delete_days=None):
        if not self.auth_manager.is_authenticated():
            return False
        if not scan_with_clamscan(file_path):
            move_to_quarantine(file_path)
            QMessageBox.critical(None, "Virus Detected",
                                 "The file appears to contain malware and has been moved to quarantine.")
            return False

        encrypted_path = encrypt_file(file_path, self.auth_manager.encryption_key)
        file_id = str(uuid.uuid4())
        upload_date = datetime.datetime.now().isoformat()
        auto_delete_date = (
            (datetime.datetime.now() + datetime.timedelta(days=auto_delete_days)).isoformat()
            if auto_delete_days else None
        )
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO files (id, original_name, encrypted_path, upload_date, auto_delete_date, user_id) VALUES (?, ?, ?, ?, ?, ?)",
            (file_id, Path(file_path).name, str(encrypted_path), upload_date, auto_delete_date, self.auth_manager.current_user["id"])
        )
        conn.commit()
        conn.close()
        logger.info(f"File {file_path} added to vault as {encrypted_path}.")
        return True

    def get_user_files(self):
        if not self.auth_manager.is_authenticated():
            return []
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, original_name, encrypted_path, upload_date, auto_delete_date FROM files WHERE user_id = ?",
            (self.auth_manager.current_user["id"],)
        )
        files = [{"id": row[0], "name": row[1], "path": row[2], "upload_date": row[3], "auto_delete_date": row[4]} for row in cursor.fetchall()]
        conn.close()
        return files

    def delete_file(self, file_id):
        if not self.auth_manager.is_authenticated():
            return False
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_path FROM files WHERE id = ? AND user_id = ?", (file_id, self.auth_manager.current_user["id"]))
        result = cursor.fetchone()
        if result:
            encrypted_path = Path(result[0])
            secure_delete_file(encrypted_path)
            cursor.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()
            logger.info(f"File {file_id} deleted from vault.")
            conn.close()
            return True
        conn.close()
        return False

# UI Components with Adjusted Alignments
class LoginWidget(QWidget):
    def __init__(self, auth_manager):
        super().__init__()
        self.auth_manager = auth_manager
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(15)

        title = QLabel("Login or Register")
        title.setFont(QFont("Arial", 16))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.username_input.setFixedWidth(300)
        # Pre-fill username if session exists but auto-login failed
        session_data = load_session()
        if session_data:
            self.username_input.setText(session_data.get("username", ""))
        layout.addWidget(self.username_input, alignment=Qt.AlignmentFlag.AlignCenter)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Password")
        self.password_input.setFixedWidth(300)
        layout.addWidget(self.password_input, alignment=Qt.AlignmentFlag.AlignCenter)

        self.totp_input = QLineEdit()
        self.totp_input.setPlaceholderText("TOTP Code (if MFA enabled)")
        self.totp_input.setFixedWidth(300)
        layout.addWidget(self.totp_input, alignment=Qt.AlignmentFlag.AlignCenter)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(20)

        login_button = QPushButton("Login")
        login_button.clicked.connect(self.login)
        login_button.setFixedWidth(120)
        button_layout.addWidget(login_button)

        register_button = QPushButton("Register")
        register_button.clicked.connect(self.register)
        register_button.setFixedWidth(120)
        button_layout.addWidget(register_button)

        layout.addLayout(button_layout)

        self.totp_checkbox = QCheckBox("Enable TOTP for Registration")
        layout.addWidget(self.totp_checkbox, alignment=Qt.AlignmentFlag.AlignCenter)

        self.setLayout(layout)

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        totp_code = self.totp_input.text() or None
        if self.auth_manager.login(username, password, totp_code):
            self.parent().parent().stack.setCurrentWidget(self.parent().parent().vault_widget)
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid credentials or TOTP code.")

    def register(self):
        username = self.username_input.text()
        password = self.password_input.text()
        success, totp_secret = self.auth_manager.register_user(username, password)
        if success:
            msg = "Registration successful."
            if totp_secret:
                msg += f"\nYour TOTP secret is: {totp_secret}\nSave this securely and scan it with an authenticator app!"
            QMessageBox.information(self, "Success", msg)
            # Auto-switch to vault after registration
            self.parent().parent().stack.setCurrentWidget(self.parent().parent().vault_widget)
        else:
            QMessageBox.warning(self, "Registration Failed", "Username already exists.")

class VaultWidget(QWidget):
    def __init__(self, file_manager):
        super().__init__()
        self.file_manager = file_manager
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(15)

        header_layout = QHBoxLayout()
        header_layout.setAlignment(Qt.AlignmentFlag.AlignRight)

        # Add ClamAV Settings button
        clamav_button = QPushButton("ClamAV Settings")
        clamav_button.clicked.connect(self.open_clamav_settings)
        clamav_button.setFixedWidth(120)
        header_layout.addWidget(clamav_button)

        # Add Logout button
        logout_button = QPushButton("Logout")
        logout_button.clicked.connect(self.logout)
        logout_button.setFixedWidth(120)
        header_layout.addWidget(logout_button)

        layout.addLayout(header_layout)

        self.drop_list = self.DropFileListWidget(self.file_manager)
        self.drop_list.setFixedHeight(200)
        layout.addWidget(self.drop_list)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(20)

        self.add_button = QPushButton("Add File")
        self.add_button.clicked.connect(self.add_file)
        self.add_button.setFixedWidth(120)
        button_layout.addWidget(self.add_button)

        self.extract_button = QPushButton("Extract Selected")
        self.extract_button.clicked.connect(self.extract_file)
        self.extract_button.setFixedWidth(120)
        button_layout.addWidget(self.extract_button)

        self.delete_button = QPushButton("Delete Selected")
        self.delete_button.clicked.connect(self.delete_file)
        self.delete_button.setFixedWidth(120)
        button_layout.addWidget(self.delete_button)

        layout.addLayout(button_layout)

        self.auto_delete_combo = QComboBox()
        self.auto_delete_combo.addItem("No Auto-Delete", None)
        self.auto_delete_combo.addItem("1 Day", 1)
        self.auto_delete_combo.addItem("7 Days", 7)
        self.auto_delete_combo.addItem("30 Days", 30)
        self.auto_delete_combo.setFixedWidth(300)
        layout.addWidget(QLabel("Auto-Delete After:"))
        layout.addWidget(self.auto_delete_combo, alignment=Qt.AlignmentFlag.AlignCenter)

        self.setLayout(layout)

    def logout(self):
        self.file_manager.auth_manager.logout()
        self.parent().parent().stack.setCurrentWidget(self.parent().parent().login_widget)
        QMessageBox.information(self, "Logged Out", "You have been logged out successfully.")

    def add_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Add")
        if file_path:
            auto_delete_days = self.auto_delete_combo.currentData()
            if self.file_manager.add_file(file_path, auto_delete_days):
                self.drop_list.refresh_files()
                QMessageBox.information(self, "Success", "File added to vault.")

    def extract_file(self):
        selected_items = self.drop_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "No file selected.")
            return
        item = selected_items[0]
        file_data = item.data(Qt.ItemDataRole.UserRole)
        output_dir = EXTRACTED_DIR
        output_path = output_dir / file_data["name"]
        decrypted_path = decrypt_file(Path(file_data["path"]), self.file_manager.auth_manager.encryption_key, output_path)
        QMessageBox.information(self, "Success", f"File extracted to {decrypted_path}")

    def delete_file(self):
        selected_items = self.drop_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "No file selected.")
            return
        item = selected_items[0]
        file_data = item.data(Qt.ItemDataRole.UserRole)
        if self.file_manager.delete_file(file_data["id"]):
            self.drop_list.refresh_files()
            QMessageBox.information(self, "Success", "File deleted from vault.")

    def open_clamav_settings(self):
        """Open the ClamAV configuration dialog"""
        dialog = ClamAVConfigDialog(self)
        dialog.exec()

    class DropFileListWidget(QListWidget):
        def __init__(self, file_manager):
            super().__init__()
            self.file_manager = file_manager
            self.setAcceptDrops(True)
            self.refresh_files()

        def dragEnterEvent(self, event: QDragEnterEvent):
            if event.mimeData().hasUrls():
                event.acceptProposedAction()

        def dropEvent(self, event: QDropEvent):
            for url in event.mimeData().urls():
                file_path = Path(url.toLocalFile())
                if file_path.is_file():
                    self.file_manager.add_file(str(file_path))
            self.refresh_files()
            event.acceptProposedAction()

        def refresh_files(self):
            self.clear()
            files = self.file_manager.get_user_files()
            for file in files:
                item = QListWidgetItem(file["name"])
                item.setData(Qt.ItemDataRole.UserRole, file)
                self.addItem(item)

# ClamAV Configuration Dialog
class ClamAVConfigDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ClamAV Configuration")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Path to ClamAV
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("ClamAV Path:"))
        self.path_input = QLineEdit()
        self.path_input.setText(load_config().get("clamav_path", ""))
        path_layout.addWidget(self.path_input)
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_clamav)
        path_layout.addWidget(browse_button)
        layout.addLayout(path_layout)

        # Test ClamAV
        test_button = QPushButton("Test ClamAV")
        test_button.clicked.connect(self.test_clamav)
        layout.addWidget(test_button)

        # Buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save")
        save_button.clicked.connect(self.save_config)
        button_layout.addWidget(save_button)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def browse_clamav(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select ClamAV Executable", 
                                             filter="Executables (*.exe)")
        if path:
            self.path_input.setText(path)

    def test_clamav(self):
        path = self.path_input.text()
        try:
            if not os.path.exists(path):
                QMessageBox.critical(self, "ClamAV Test Failed", f"File not found: {path}")
                return

            result = subprocess.run([path, "--version"], capture_output=True, text=True)
            QMessageBox.information(self, "ClamAV Test", f"ClamAV is working!\n\n{result.stdout}")
        except Exception as e:
            QMessageBox.critical(self, "ClamAV Test Failed", f"Error: {e}")

    def save_config(self):
        config = load_config()
        config["clamav_path"] = self.path_input.text()
        save_config(config)
        QMessageBox.information(self, "Configuration Saved", "ClamAV configuration has been saved.")
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.auth_manager = AuthManager(DB_PATH)
        self.file_manager = FileManager(DB_PATH, self.auth_manager)
        self.setWindowTitle("Secure File Vault")
        self.setGeometry(100, 100, 800, 600)
        self.init_ui()

    def init_ui(self):
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.login_widget = LoginWidget(self.auth_manager)
        self.vault_widget = VaultWidget(self.file_manager)

        self.stack.addWidget(self.login_widget)
        self.stack.addWidget(self.vault_widget)

        # Check for auto-login
        if self.auth_manager.auto_login():
            self.stack.setCurrentWidget(self.vault_widget)
        else:
            self.stack.setCurrentWidget(self.login_widget)

def main():
    init_database()
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
