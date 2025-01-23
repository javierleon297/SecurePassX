import sqlite3
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class DatabaseManager:
    def __init__(self, db_name="passwords.db"):
        self.conn = sqlite3.connect(db_name)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                url TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth (
                id INTEGER PRIMARY KEY,
                salt BLOB NOT NULL,
                master_check BLOB NOT NULL
            )
        ''')
        self.conn.commit()
    
    def is_first_run(self) -> bool:
        cursor = self.conn.cursor()
        cursor.execute('SELECT salt FROM auth')
        return cursor.fetchone() is None
    
    def initialize_master_password(self, master_password: str):
        salt = os.urandom(16)
        key = self._generate_key(master_password, salt)
        cipher = Fernet(key)
        master_check = cipher.encrypt(b"master_password_validation")
        
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO auth (salt, master_check) VALUES (?, ?)', (salt, master_check))
        self.conn.commit()
    
    def verify_master_password(self, master_password: str) -> bool:
        cursor = self.conn.cursor()
        cursor.execute('SELECT salt, master_check FROM auth')
        result = cursor.fetchone()
        
        if not result:
            return False
        
        salt, master_check = result
        key = self._generate_key(master_password, salt)
        
        try:
            Fernet(key).decrypt(master_check)
            return True
        except:
            return False
    
    def add_entry(self, title: str, username: str, password: str, master_password: str, url: str = ""):
        cursor = self.conn.cursor()
        cursor.execute('SELECT salt FROM auth')
        salt = cursor.fetchone()[0]
        
        key = self._generate_key(master_password, salt)
        cipher = Fernet(key)
        encrypted_password = cipher.encrypt(password.encode())
        
        cursor.execute('''
            INSERT INTO entries (title, username, encrypted_password, url)
            VALUES (?, ?, ?, ?)
        ''', (title, username, encrypted_password, url))
        self.conn.commit()
    
    def get_all_entries(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT id, title, username, url FROM entries')
        return cursor.fetchall()
    
    def get_password(self, entry_id: int, master_password: str) -> str:
        cursor = self.conn.cursor()
        cursor.execute('SELECT salt FROM auth')
        salt = cursor.fetchone()[0]
        
        cursor.execute('SELECT encrypted_password FROM entries WHERE id = ?', (entry_id,))
        encrypted_password = cursor.fetchone()[0]
        
        key = self._generate_key(master_password, salt)
        return Fernet(key).decrypt(encrypted_password).decode()
    
    def delete_entry(self, entry_id: int):
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM entries WHERE id = ?', (entry_id,))
        self.conn.commit()
    
    def _generate_key(self, master_password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))