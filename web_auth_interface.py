"""
Веб-интерфейс для системы аутентификации
Позволяет интегрировать систему аутентификации с веб-сайтами
"""

from flask import Flask, request, jsonify, session
from auth_system import AuthSystem
import os
import secrets
import time


class WebAuthInterface:
    """
    Класс для создания веб-интерфейса аутентификации
    """
    
    def __init__(self, secret_key: str = "your-secret-key-change-this"):
        self.app = Flask(__name__)
        self.app.secret_key = secret_key or secrets.token_hex(32)  # Используем надежный случайный ключ, если не предоставлен
        # Настройка безопасности сессии
        self.app.config.update(
            SESSION_COOKIE_SECURE=True,  # Куки только по HTTPS
            SESSION_COOKIE_HTTPONLY=True,  # Защита от XSS
            SESSION_COOKIE_SAMESITE='Lax',  # Защита от CSRF
        )
        self.auth_system = AuthSystem()
        
        # Настройка маршрутов
        self._setup_routes()
    
    def _generate_csrf_token(self):
        """
        Генерирует CSRF-токен
        """
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(16)
        return session['csrf_token']
    
    def _validate_csrf_token(self):
        """
        Проверяет CSRF-токен
        """
        token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token') or request.json.get('csrf_token') if request.json else None
        return token and 'csrf_token' in session and token == session['csrf_token']
    
    def _setup_routes(self):
        """
        Настраивает маршруты для аутентификации
        """
        @self.app.route('/register', methods=['POST'])
        def register():
            try:
                # Проверяем CSRF-токен для POST-запросов
                if not self._validate_csrf_token():
                    return jsonify({'success': False, 'message': 'Неверный CSRF-токен'}), 403
                
                data = request.get_json()
                if not data:
                    return jsonify({'success': False, 'message': 'Нет данных'}), 400
                
                username = data.get('username')
                password = data.get('password')
                
                if not username or not password:
                    return jsonify({'success': False, 'message': 'Требуется имя пользователя и пароль'}), 400
                
                # Получаем IP-адрес клиента для проверки частых попыток регистрации
                client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                success, message = self.auth_system.register(username, password, identifier=client_ip)
                return jsonify({'success': success, 'message': message})
            
            except Exception as e:
                return jsonify({'success': False, 'message': f'Ошибка сервера: {str(e)}'}), 500
        
        @self.app.route('/login', methods=['POST'])
        def login():
            try:
                # Проверяем CSRF-токен для POST-запросов
                if not self._validate_csrf_token():
                    return jsonify({'success': False, 'message': 'Неверный CSRF-токен'}), 403
                
                data = request.get_json()
                if not data:
                    return jsonify({'success': False, 'message': 'Нет данных'}), 400
                
                username = data.get('username')
                password = data.get('password')
                
                if not username or not password:
                    return jsonify({'success': False, 'message': 'Требуется имя пользователя и пароль'}), 400
                
                success, message = self.auth_system.login(username, password)
                
                if success:
                    # Обновляем сессию для предотвращения фиксации сессии
                    session.permanent = True  # Делаем сессию перманентной (но она все равно будет удалена при logout)
                    session['username'] = username
                    session['login_time'] = time.time()  # Запоминаем время входа
                    session['session_id'] = secrets.token_hex(16)  # Добавляем уникальный идентификатор сессии
                    # Обновляем CSRF-токен после успешного входа
                    session['csrf_token'] = secrets.token_hex(16)
                    return jsonify({
                        'success': True,
                        'message': message,
                        'username': username,
                        'csrf_token': session['csrf_token']
                    })
                else:
                    return jsonify({'success': False, 'message': message})
            
            except Exception as e:
                return jsonify({'success': False, 'message': f'Ошибка сервера: {str(e)}'}), 500
        
        @self.app.route('/logout', methods=['POST'])
        def logout():
            try:
                # Проверяем CSRF-токен для POST-запросов
                if not self._validate_csrf_token():
                    return jsonify({'success': False, 'message': 'Неверный CSRF-токен'}), 403
                
                # Полностью очищаем сессию для обеспечения безопасности
                session.clear()
                return jsonify({'success': True, 'message': 'Выход выполнен успешно'})
            
            except Exception as e:
                return jsonify({'success': False, 'message': f'Ошибка сервера: {str(e)}'}), 500
        
        @self.app.route('/change_password', methods=['POST'])
        def change_password():
            try:
                # Проверяем CSRF-токен для POST-запросов
                if not self._validate_csrf_token():
                    return jsonify({'success': False, 'message': 'Неверный CSRF-токен'}), 403
                
                if 'username' not in session:
                    return jsonify({'success': False, 'message': 'Требуется вход в систему'}), 401
                
                data = request.get_json()
                if not data:
                    return jsonify({'success': False, 'message': 'Нет данных'}), 400
                
                username = session['username']
                old_password = data.get('old_password')
                new_password = data.get('new_password')
                
                if not old_password or not new_password:
                    return jsonify({'success': False, 'message': 'Требуется старый и новый пароли'}), 400
                
                success, message = self.auth_system.change_password(username, old_password, new_password)
                return jsonify({'success': success, 'message': message})
            
            except Exception as e:
                return jsonify({'success': False, 'message': f'Ошибка сервера: {str(e)}'}), 500
        
        @self.app.route('/delete_account', methods=['POST'])
        def delete_account():
            try:
                # Проверяем CSRF-токен для POST-запросов
                if not self._validate_csrf_token():
                    return jsonify({'success': False, 'message': 'Неверный CSRF-токен'}), 403
                
                if 'username' not in session:
                    return jsonify({'success': False, 'message': 'Требуется вход в систему'}), 401
                
                data = request.get_json()
                if not data:
                    return jsonify({'success': False, 'message': 'Нет данных'}), 400
                
                username = session['username']
                password = data.get('password')
                
                if not password:
                    return jsonify({'success': False, 'message': 'Требуется пароль'}), 400
                
                success, message = self.auth_system.delete_user(username, password)
                
                if success:
                    session.pop('username', None)  # Выходим из системы после удаления аккаунта
                    # Удаляем CSRF-токен при выходе
                    session.pop('csrf_token', None)
                
                return jsonify({'success': success, 'message': message})
            
            except Exception as e:
                return jsonify({'success': False, 'message': f'Ошибка сервера: {str(e)}'}), 500
        
        @self.app.route('/check_session', methods=['GET'])
        def check_session():
            try:
                response_data = {
                    'logged_in': 'username' in session
                }
                if 'username' in session:
                    response_data['username'] = session['username']
                
                # Всегда включаем CSRF-токен в ответ
                response_data['csrf_token'] = self._generate_csrf_token()
                
                return jsonify(response_data)
            
            except Exception as e:
                return jsonify({'success': False, 'message': f'Ошибка сервера: {str(e)}'}), 500
        
        @self.app.route('/get_csrf_token', methods=['GET'])
        def get_csrf_token():
            """
            Возвращает CSRF-токен для использования в формах
            """
            try:
                token = self._generate_csrf_token()
                return jsonify({'csrf_token': token})
            except Exception as e:
                return jsonify({'success': False, 'message': f'Ошибка сервера: {str(e)}'}), 500
    
    def run(self, host: str = '127.0.0.1', port: int = 5000, debug: bool = False):
        """
        Запускает веб-сервер
        """
        self.app.run(host=host, port=port, debug=debug)


def create_web_auth_app():
    """
    Функция для создания и настройки веб-приложения аутентификации
    """
    web_auth = WebAuthInterface()
    return web_auth.app


if __name__ == "__main__":
    # Создаем экземпляр веб-интерфейса
    web_auth_interface = WebAuthInterface()
    
    # Запускаем сервер (обычно это делается в отдельном процессе)
    print("Веб-интерфейс аутентификации запущен на http://127.0.0.1:5000")
    print("Доступные маршруты:")
    print("  POST /register - регистрация пользователя")
    print("  POST /login - вход в систему")
    print("  POST /logout - выход из системы")
    print("  POST /change_password - изменение пароля")
    print(" POST /delete_account - удаление аккаунта")
    print("  GET /check_session - проверка сессии")
    
    # Запускаем сервер в режиме отладки
    web_auth_interface.run(debug=True)