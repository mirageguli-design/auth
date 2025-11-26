"""
Основное веб-приложение с интегрированной системой аутентификации
"""

from web_auth_interface import create_web_auth_app
from flask import render_template_string, send_from_directory
import os


def create_app():
    """
    Создает и настраивает Flask-приложение с аутентификацией
    """
    app = create_web_auth_app()
    
    # Маршрут для главной страницы
    @app.route('/')
    def index():
        # Отправляем HTML-страницу с аутентификацией
        with open('templates/index.html', 'r', encoding='utf-8') as f:
            return f.read()
    
    # Маршрут для статических файлов (если нужно)
    @app.route('/static/<path:filename>')
    def static_files(filename):
        return send_from_directory('static', filename)
    
    return app


if __name__ == "__main__":
    # Создаем приложение
    app = create_app()
    
    # Проверяем, существует ли папка для шаблонов
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # Определяем порт из переменной окружения или используем 5000 по умолчанию
    port = int(os.environ.get('PORT', 5000))
    
    # Запускаем приложение
    print("Запуск веб-приложения с системой аутентификации...")
    print(f"Приложение доступно на порту: {port}")
    # В продакшене (на Heroku) отключаем debug и слушаем на 0.0.0.0
    app.run(debug=False, host='0.0.0', port=port)