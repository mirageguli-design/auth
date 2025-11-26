"""
Система аутентификации с использованием ООП
Реализует хеширование паролей, валидацию ввода и безопасное хранение данных
"""

import bcrypt
import re
import os
import logging
from typing import Optional, List, Tuple
import time


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


class User:
    """
    Класс для представления пользователя
    """
    
    def __init__(self, username: str, password: str):
        self.username = username
        self.password_hash = PasswordHasher.hash_password(password)
    
    def check_password(self, password: str) -> bool:
        """
        Проверяет, соответствует ли введенный пароль хешу
        """
        return PasswordHasher.verify_password(password, self.password_hash)
    
    def to_dict(self) -> dict:
        """
        Возвращает словарь с данными пользователя
        """
        return {
            'username': self.username,
            'password_hash': self.password_hash
        }
    
    @classmethod
    def from_dict(cls, data: dict):
        """
        Создает объект User из словаря
        """
        user = cls.__new__(cls)
        user.username = data['username']
        user.password_hash = data['password_hash']
        return user


class HashTable:
    """
    Хеш-таблица для хранения пользователей
    """
    
    def __init__(self, size: int = 5):
        self.size = size
        self.table = [[] for _ in range(size)]  # Метод цепочек для разрешения коллизий
        self.count = 0  # Количество элементов в хеш-таблице
        self.collision_count = 0  # Количество коллизий для оценки производительности
    
    def _hash(self, key: str) -> int:
        """
        Улучшенная хеш-функция с лучшим распределением
        """
        hash_value = 0
        for char in key:
            hash_value = (hash_value * 31 + ord(char)) % (2**32)  # Используем 31 как множитель, как в Java
        return hash_value % self.size
    
    def insert(self, user: User) -> bool:
        """
        Вставляет пользователя в хеш-таблицу
        """
        # Проверяем, нужно ли увеличить размер таблицы (если коэффициент заполнения > 0.75)
        if self.count >= self.size * 0.75:
            self._resize()
        
        index = self._hash(user.username)
        
        # Если в этом индексе уже есть элементы, это потенциальная коллизия
        if len(self.table[index]) > 0:
            self.collision_count += 1 # Увеличиваем счетчик коллизий
        
        # Проверяем, не существует ли уже пользователь с таким именем
        for i, existing_user in enumerate(self.table[index]):
            if existing_user.username == user.username:
                self.table[index][i] = user  # Обновляем пользователя
                return True
        
        # Добавляем нового пользователя
        self.table[index].append(user)
        self.count += 1  # Увеличиваем счетчик элементов
        return True
    
    def search(self, username: str) -> Optional[User]:
        """
        Ищет пользователя по имени
        """
        index = self._hash(username)
        
        for user in self.table[index]:
            if user.username == username:
                return user
        
        return None
    
    def delete(self, username: str) -> bool:
        """
        Удаляет пользователя по имени
        """
        index = self._hash(username)
        
        for i, user in enumerate(self.table[index]):
            if user.username == username:
                del self.table[index][i]
                self.count -= 1  # Уменьшаем счетчик элементов
                return True
        
        return False
    
    def get_all_usernames(self) -> List[str]:
        """
        Возвращает список всех имен пользователей
        """
        usernames = []
        for bucket in self.table:
            for user in bucket:
                usernames.append(user.username)
        return usernames
    
    def _resize(self):
        """
        Увеличивает размер хеш-таблицы и перехеширует все элементы
        """
        # Сохраняем текущие элементы
        old_table = []
        for bucket in self.table:
            for user in bucket:
                old_table.append(user)
        
        # Увеличиваем размер вдвое
        old_size = self.size
        self.size *= 2
        self.count = 0  # Сбрасываем счетчик, он будет увеличиваться при вставке
        
        # Создаем новую таблицу
        self.table = [[] for _ in range(self.size)]
        
        # Перехешируем все элементы
        for user in old_table:
            self.insert(user)


class AuthSystem:
    """
    Основной класс системы аутентификации
    """
    
    def __init__(self, data_file: str = "data/users.db"):
        self.data_file = data_file
        # Создаем директорию для файла данных, если она не существует
        os.makedirs(os.path.dirname(self.data_file), exist_ok=True)
        # Создаем пустой файл, если он не существует
        if not os.path.exists(self.data_file):
            with open(self.data_file, 'w', encoding='utf-8') as f:
                pass
        self.users = HashTable()
        self._setup_logging() # Настройка логирования
        self.failed_login_attempts = {}  # Словарь для отслеживания неудачных попыток входа
        self.blocked_users = {}  # Словарь для отслеживания заблокированных пользователей и времени разблокировки
        self.max_failed_attempts = 5  # Максимальное количество неудачных попыток входа
        self.block_duration = 300  # Время блокировки в секундах (5 минут)
        self.registration_attempts = {}  # Словарь для отслеживания попыток регистрации по IP или времени
        self.max_registration_attempts = 5  # Максимальное количество попыток регистрации за интервал
        self.registration_attempt_window = 300  # Временной интервал для учета попыток регистрации в секундах (5 минут)
        self.user_cache = {}  # Кэш для пользователей
        self.cache_timeout = 300  # Время жизни кэша в секундах (5 минут)
        self._load_data()
    
    def _setup_logging(self):
        """
        Настраивает систему логирования
        """
        # Создаем логгер
        self.logger = logging.getLogger(f"AuthSystem_{id(self)}")
        self.logger.setLevel(logging.INFO)
        
        # Создаем обработчик для записи логов в файл
        if not self.logger.handlers:
            handler = logging.FileHandler("auth_system.log", encoding='utf-8')
            handler.setLevel(logging.INFO)
            
            # Создаем форматтер для логов
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            
            # Добавляем обработчик к логгеру
            self.logger.addHandler(handler)
    
    def _load_data(self):
        """
        Загружает данные пользователей из файла
        """
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    # Применяем блокировку файла в зависимости от ОС (разделяемая блокировка)
                    try:
                        import fcntl  # Unix-системы
                        fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # Разделяемая блокировка
                    except ImportError:
                        try:
                            import msvcrt  # Windows
                            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)  # Блокировка
                        except ImportError:
                            pass  # Если не удалось импортировать ни одну библиотеку, продолжаем без блокировки
                    
                    lines = f.readlines()
                    
                    # Снимаем блокировку
                    try:
                        import fcntl  # Unix-системы
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)  # Снятие блокировки
                    except ImportError:
                        try:
                            import msvcrt  # Windows
                            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)  # Снятие блокировки
                        except ImportError:
                            pass
                    
                    for line in lines:
                        line = line.strip()
                        if line:
                            username, password_hash = line.split(':', 1)
                            user = User.__new__(User)
                            user.username = username
                            user.password_hash = password_hash
                            self.users.insert(user)
            except Exception as e:
                print(f"Ошибка при загрузке данных: {e}")
    
    def _save_data(self):
        """
        Сохраняет данные пользователей в файл атомарно
        """
        try:
            # Создаем директорию, если она не существует
            os.makedirs(os.path.dirname(self.data_file), exist_ok=True)
            
            # Создаем временный файл
            temp_file = self.data_file + '.tmp'
            with open(temp_file, 'w', encoding='utf-8') as f:
                # Применяем блокировку файла в зависимости от ОС
                try:
                    import fcntl  # Unix-системы
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)  # Эксклюзивная блокировка
                except ImportError:
                    try:
                        import msvcrt # Windows
                        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)  # Блокировка
                    except ImportError:
                        pass  # Если не удалось импортировать ни одну библиотеку, продолжаем без блокировки
                
                usernames = self.users.get_all_usernames()
                for username in usernames:
                    user = self.users.search(username)
                    if user:
                        f.write(f"{user.username}:{user.password_hash}\n")
                
                # Снимаем блокировку
                try:
                    import fcntl  # Unix-системы
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)  # Снятие блокировки
                except ImportError:
                    try:
                        import msvcrt  # Windows
                        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1) # Снятие блокировки
                    except ImportError:
                        pass

            # Атомарно переименовываем временный файл в основной
            os.replace(temp_file, self.data_file)
            
            # Очищаем кэш после сохранения данных, так как данные могли измениться
            self.user_cache.clear()
        except Exception as e:
            print(f"Ошибка при сохранении данных: {e}")
            # Удаляем временный файл в случае ошибки
            try:
                os.remove(temp_file)
            except:
                pass
    
    def _is_user_blocked(self, username: str) -> bool:
        """
        Проверяет, заблокирован ли пользователь
        """
        import time
        if username in self.blocked_users:
            # Если время блокировки истекло, удаляем пользователя из списка заблокированных
            if time.time() > self.blocked_users[username]:
                del self.blocked_users[username]
                # Также сбрасываем счетчик неудачных попыток
                if username in self.failed_login_attempts:
                    del self.failed_login_attempts[username]
                return False
            return True
        return False
    
    def _update_failed_attempts(self, username: str) -> bool:
        """
        Обновляет счетчик неудачных попыток входа и блокирует пользователя при необходимости
        """
        import time
        current_time = time.time()
        
        # Если пользователь уже заблокирован, возвращаем True (заблокирован)
        if self._is_user_blocked(username):
            return True
        
        # Обновляем счетчик неудачных попыток
        if username in self.failed_login_attempts:
            self.failed_login_attempts[username] += 1
        else:
            self.failed_login_attempts[username] = 1
        
        # Проверяем, нужно ли блокировать пользователя
        if self.failed_login_attempts[username] >= self.max_failed_attempts:
            self.blocked_users[username] = current_time + self.block_duration
            self.logger.info(f"Пользователь '{username}' заблокирован на {self.block_duration} секунд из-за превышения количества неудачных попыток входа")
            return True
        
        return False
        
        return False
    
    def _check_registration_attempts(self, identifier: str = "default") -> bool:
        """
        Проверяет, не превышено ли количество попыток регистрации для идентификатора (например, IP-адреса)
        Возвращает True, если регистрация разрешена, False - если ограничение превышено
        """
        import time
        current_time = time.time()
        
        # Очищаем старые попытки регистрации за пределами временного окна
        if identifier in self.registration_attempts:
            self.registration_attempts[identifier] = [
                timestamp for timestamp in self.registration_attempts[identifier]
                if current_time - timestamp < self.registration_attempt_window
            ]
        else:
            self.registration_attempts[identifier] = []
        
        # Проверяем, не превышено ли максимальное количество попыток
        if len(self.registration_attempts[identifier]) >= self.max_registration_attempts:
            self.logger.warning(f"Превышено максимальное количество попыток регистрации для идентификатора '{identifier}'")
            return False
        
        # Добавляем текущую попытку
        self.registration_attempts[identifier].append(current_time)
        return True
    
    def _get_cached_user(self, username: str) -> Optional[User]:
        """
        Получает пользователя из кэша, если он там есть и не устарел
        """
        if username in self.user_cache:
            user_data, timestamp = self.user_cache[username]
            # Проверяем, не устарел ли кэш
            if time.time() - timestamp < self.cache_timeout:
                return user_data
            else:
                # Удаляем устаревший кэш
                del self.user_cache[username]
        return None

    def _cache_user(self, username: str, user: User):
        """
        Кэширует пользователя
        """
        self.user_cache[username] = (user, time.time())
    
    def register(self, username: str, password: str, identifier: str = "default") -> Tuple[bool, str]:
        """
        Регистрирует нового пользователя
        identifier - идентификатор источника запроса (например, IP-адрес) для проверки частых попыток регистрации
        """
        # Проверяем, не превышено ли количество попыток регистрации
        if not self._check_registration_attempts(identifier):
            self.logger.warning(f"Неудачная попытка регистрации пользователя '{username}' из-за превышения лимита попыток регистрации (идентификатор: {identifier})")
            return False, "Слишком много попыток регистрации. Пожалуйста, повторите позже."
        
        # Валидация ввода
        username_valid, username_msg = InputValidator.validate_username(username)
        if not username_valid:
            self.logger.warning(f"Неудачная попытка регистрации пользователя '{username}': {username_msg}")
            return False, username_msg
        
        password_valid, password_msg = InputValidator.validate_password(password)
        if not password_valid:
            self.logger.warning(f"Неудачная попытка регистрации пользователя '{username}': {password_msg}")
            return False, password_msg
        
        # Проверяем, существует ли уже пользователь с таким именем
        if self.users.search(username):
            self.logger.warning(f"Неудачная попытка регистрации пользователя '{username}': пользователь уже существует")
            return False, "Пользователь с таким именем уже существует"
        
        # Создаем нового пользователя
        user = User(username, password)
        
        # Добавляем пользователя в таблицу
        self.users.insert(user)
        
        # Сохраняем данные
        self._save_data()
        
        # Удаляем пользователя из кэша, если он там был
        if username in self.user_cache:
            del self.user_cache[username]
        
        self.logger.info(f"Пользователь '{username}' успешно зарегистрирован")
        return True, "Регистрация прошла успешно"
    
    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Аутентифицирует пользователя
        """
        # Проверяем, заблокирован ли пользователь
        if self._is_user_blocked(username):
            self.logger.warning(f"Попытка входа заблокированным пользователем '{username}'")
            return False, f"Пользователь заблокирован. Повторите попытку через {self.block_duration} секунд"
        
        # Проверяем, существует ли пользователь (с использованием кэша)
        user = self._get_cached_user(username)
        if not user:
            user = self.users.search(username)
            if user:
                # Кэшируем найденного пользователя
                self._cache_user(username, user)
        if not user:
            self.logger.warning(f"Неудачная попытка входа пользователя '{username}': пользователь не найден")
            # Даже если пользователь не существует, мы все равно увеличиваем счетчик неудачных попыток
            # чтобы предотвратить перебор имен пользователей
            self._update_failed_attempts(username)
            return False, "Пользователь не найден"
        
        # Проверяем пароль
        if user.check_password(password):
            # Успешный вход - сбрасываем счетчик неудачных попыток
            if username in self.failed_login_attempts:
                del self.failed_login_attempts[username]
            self.logger.info(f"Пользователь '{username}' успешно вошел в систему")
            return True, "Вход выполнен успешно"
        else:
            # Неудачная попытка входа - обновляем счетчик
            is_blocked = self._update_failed_attempts(username)
            self.logger.warning(f"Неудачная попытка входа пользователя '{username}': неверный пароль")
            if is_blocked:
                return False, f"Пользователь заблокирован из-за превышения количества неудачных попыток. Повторите попытку через {self.block_duration} секунд"
            return False, "Неверный пароль"
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """
        Изменяет пароль пользователя
        """
        # Проверяем, существует ли пользователь (с использованием кэша)
        user = self._get_cached_user(username)
        if not user:
            user = self.users.search(username)
            if user:
                # Кэшируем найденного пользователя
                self._cache_user(username, user)
        if not user:
            self.logger.warning(f"Неудачная попытка изменения пароля для пользователя '{username}': пользователь не найден")
            return False, "Пользователь не найден"
        
        # Проверяем старый пароль
        if not user.check_password(old_password):
            self.logger.warning(f"Неудачная попытка изменения пароля для пользователя '{username}': неверный старый пароль")
            return False, "Неверный старый пароль"
        
        # Валидируем новый пароль
        password_valid, password_msg = InputValidator.validate_password(new_password)
        if not password_valid:
            self.logger.warning(f"Неудачная попытка изменения пароля для пользователя '{username}': {password_msg}")
            return False, password_msg
        
        # Обновляем пароль
        user.password_hash = PasswordHasher.hash_password(new_password)
        
        # Сохраняем изменения
        self._save_data()
        
        # Обновляем пользователя в кэше
        self._cache_user(username, user)
        
        self.logger.info(f"Пароль для пользователя '{username}' успешно изменен")
        return True, "Пароль успешно изменен"
    
    def delete_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        Удаляет пользователя
        """
        # Проверяем, существует ли пользователь (с использованием кэша)
        user = self._get_cached_user(username)
        if not user:
            user = self.users.search(username)
            if user:
                # Кэшируем найденного пользователя
                self._cache_user(username, user)
        if not user:
            self.logger.warning(f"Неудачная попытка удаления пользователя '{username}': пользователь не найден")
            return False, "Пользователь не найден"
        
        # Проверяем пароль
        if not user.check_password(password):
            self.logger.warning(f"Неудачная попытка удаления пользователя '{username}': неверный пароль")
            return False, "Неверный пароль"
        
        # Удаляем пользователя из таблицы
        self.users.delete(username)
        
        # Удаляем пользователя из кэша
        if username in self.user_cache:
            del self.user_cache[username]
        
        # Сохраняем изменения
        self._save_data()
        
        self.logger.info(f"Пользователь '{username}' успешно удален")
        return True, "Пользователь успешно удален"


# Пример использования
if __name__ == "__main__":
    # Создаем экземпляр системы аутентификации
    auth = AuthSystem()
    
    # Регистрируем тестовых пользователей
    test_users = [
        ("user1", "password1"),
        ("user2", "password2"),
        ("user3", "password3"),
        ("admin", "admin123"),
        ("testuser", "test123"),
        ("demo", "demo123"),
        ("guest", "guest123"),
        ("newuser", "newuser123"),
        ("sample", "sample123"),
        ("example", "example123")
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