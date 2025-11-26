"""
Система аутентификации с использованием базы данных SQLite
"""

import bcrypt
import re
import sqlite3
import os
from typing import Optional, List, Tuple
from contextlib import contextmanager


class PasswordHasher:
    """
    Класс для безопасного хеширования паролей
    """
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Хеширует пароль с использованием bcrypt
        """
        # Преобразуем строку пароля в байты
        password_bytes = password.encode('utf-8')
        # Генерируем соль и хешируем пароль
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password_bytes, salt)
        # Возвращаем хеш в виде строки (в кодировке base64 для хранения в файле)
        return hashed.decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Проверяет, соответствует ли пароль хешированному значению
        """
        password_bytes = password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)


class InputValidator:
    """
    Класс для валидации ввода (логина и пароля)
    """
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """
        Валидирует имя пользователя
        """
        if not username:
            return False, "Имя пользователя не может быть пустым"
        
        if len(username) < 3:
            return False, "Имя пользователя должно содержать не менее 3 символов"
        
        if len(username) > 20:
            return False, "Имя пользователя должно содержать не более 20 символов"
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "Имя пользователя может содержать только буквы, цифры и подчеркивания"
        
        return True, "Имя пользователя корректно"
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, str]:
        """
        Валидирует пароль
        """
        if not password:
            return False, "Пароль не может быть пустым"
        
        if len(password) < 8:
            return False, "Пароль должен содержать не менее 8 символов"
        
        if len(password) > 128:
            return False, "Пароль должен содержать не более 128 символов"
        
        # Проверяем, содержит ли пароль хотя бы одну строчную букву
        if not re.search(r'[a-z]', password):
            return False, "Пароль должен содержать хотя бы одну строчную букву"
        
        # Проверяем, содержит ли пароль хотя бы одну заглавную букву
        if not re.search(r'[A-Z]', password):
            return False, "Пароль должен содержать хотя бы одну заглавную букву"
        
        # Проверяем, содержит ли пароль хотя бы одну цифру
        if not re.search(r'\d', password):
            return False, "Пароль должен содержать хотя бы одну цифру"
        
        # Проверяем, содержит ли пароль хотя бы один специальный символ
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Пароль должен содержать хотя бы один специальный символ (!@#$%^&*(),.?\":{}|<>)"
        
        return True, "Пароль корректен"


class DBAuthSystem:
    """
    Основной класс системы аутентификации с использованием базы данных SQLite
    """
    
    def __init__(self, db_path: str = "data/users.db"):
        self.db_path = db_path
        # Создаем директорию для файла базы данных, если она не существует
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """
        Инициализирует базу данных и создает таблицы
        """
        with self._get_db_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
    
    @contextmanager
    def _get_db_connection(self):
        """
        Контекстный менеджер для подключения к базе данных
        """
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()
    
    def register(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Регистрирует нового пользователя
        """
        # Валидация ввода
        username_valid, username_msg = InputValidator.validate_username(username)
        if not username_valid:
            return False, username_msg
        
        password_valid, password_msg = InputValidator.validate_password(password)
        if not password_valid:
            return False, password_msg
        
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                # Проверяем, существует ли уже пользователь с таким именем
                cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    return False, "Пользователь с таким именем уже существует"
                
                # Хешируем пароль
                password_hash = PasswordHasher.hash_password(password)
                
                # Вставляем нового пользователя в базу данных
                cursor.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )
                conn.commit()
                
                return True, "Регистрация прошла успешно"
        except sqlite3.IntegrityError:
            return False, "Пользователь с таким именем уже существует"
        except Exception as e:
            return False, f"Ошибка при регистрации: {str(e)}"
    
    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Аутентифицирует пользователя
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT password_hash FROM users WHERE username = ?",
                    (username,)
                )
                result = cursor.fetchone()
                
                if not result:
                    return False, "Пользователь не найден"
                
                stored_hash = result[0]
                if PasswordHasher.verify_password(password, stored_hash):
                    return True, "Вход выполнен успешно"
                else:
                    return False, "Неверный пароль"
        except Exception as e:
            return False, f"Ошибка при аутентификации: {str(e)}"
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """
        Изменяет пароль пользователя
        """
        # Валидируем новый пароль
        password_valid, password_msg = InputValidator.validate_password(new_password)
        if not password_valid:
            return False, password_msg
        
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT password_hash FROM users WHERE username = ?",
                    (username,)
                )
                result = cursor.fetchone()
                
                if not result:
                    return False, "Пользователь не найден"
                
                stored_hash = result[0]
                if not PasswordHasher.verify_password(old_password, stored_hash):
                    return False, "Неверный старый пароль"
                
                # Хешируем новый пароль
                new_password_hash = PasswordHasher.hash_password(new_password)
                
                # Обновляем пароль в базе данных
                cursor.execute(
                    "UPDATE users SET password_hash = ? WHERE username = ?",
                    (new_password_hash, username)
                )
                conn.commit()
                
                return True, "Пароль успешно изменен"
        except Exception as e:
            return False, f"Ошибка при изменении пароля: {str(e)}"
    
    def delete_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Удаляет пользователя
        """
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT password_hash FROM users WHERE username = ?",
                    (username,)
                )
                result = cursor.fetchone()
                
                if not result:
                    return False, "Пользователь не найден"
                
                stored_hash = result[0]
                if not PasswordHasher.verify_password(password, stored_hash):
                    return False, "Неверный пароль"
                
                # Удаляем пользователя из базы данных
                cursor.execute("DELETE FROM users WHERE username = ?", (username,))
                conn.commit()
                
                return True, "Пользователь успешно удален"
        except Exception as e:
            return False, f"Ошибка при удалении пользователя: {str(e)}"


# Пример использования
if __name__ == "__main__":
    # Создаем экземпляр системы аутентификации с базой данных
    auth = DBAuthSystem()
    
    # Регистрируем тестовых пользователей
    test_users = [
        ("user1", "password1!"),
        ("user2", "password2!"),
        ("user3", "password3!"),
        ("admin", "admin123!"),
        ("testuser", "test123!")
    ]
    
    print("Регистрация тестовых пользователей:")
    for username, password in test_users:
        success, message = auth.register(username, password)
        print(f"Регистрация {username}: {message}")
    
    print("\nПроверка входа:")
    for username, password in test_users[:3]:  # Проверяем первых 3 пользователей
        success, message = auth.login(username, password)
        print(f"Вход {username}: {message}")
    
    # Пример неправильного пароля
    success, message = auth.login("user1", "wrongpassword")
    print(f"Вход user1 с неправильным паролем: {message}")
