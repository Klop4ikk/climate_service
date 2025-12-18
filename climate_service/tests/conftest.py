# tests/conftest.py
import pytest
import os
import tempfile
import sys
from pathlib import Path

# Добавляем корневую директорию в путь
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import app as flask_app
from database import init_db, get_db
import hashlib

@pytest.fixture
def app():
    """Создаем тестовое приложение Flask."""
    # Используем временную базу данных
    db_fd, db_path = tempfile.mkstemp()
    
    flask_app.config.update({
        'TESTING': True,
        'SECRET_KEY': 'test-secret-key',
        'DATABASE': db_path,
        'WTF_CSRF_ENABLED': False
    })
    
    with flask_app.app_context():
        init_db(flask_app)
        # Создаем тестовые данные
        db = get_db()
        db.executescript('''
            INSERT INTO users (id, fio, phone, login, password_hash, role)
            VALUES 
                (100, 'Тест Клиент', '79990000001', 'test_client', ?, 'client'),
                (101, 'Тест Специалист', '79990000002', 'test_specialist', ?, 'specialist'),
                (102, 'Тест Оператор', '79990000003', 'test_operator', ?, 'operator'),
                (103, 'Тест Менеджер', '79990000004', 'test_manager', ?, 'manager'),
                (104, 'Тест Админ', '79990000005', 'test_admin', ?, 'admin'),
                (105, 'Тест Менеджер качества', '79990000006', 'test_quality', ?, 'quality_manager')
        ''', (
            hash_password('test123'),
            hash_password('test123'),
            hash_password('test123'),
            hash_password('test123'),
            hash_password('test123'),
            hash_password('test123')
        ))
        
        # Тестовые заявки
        db.executescript('''
            INSERT INTO repair_requests (id, client_id, equipment_type, equipment_model, problem_description, status)
            VALUES 
                (1000, 100, 'Кондиционер', 'Test Model 1', 'Тестовая проблема 1', 'new'),
                (1001, 100, 'Увлажнитель', 'Test Model 2', 'Тестовая проблема 2', 'in_progress'),
                (1002, 100, 'Обогреватель', 'Test Model 3', 'Тестовая проблема 3', 'completed')
        ''')
        db.commit()
    
    yield flask_app
    
    # Очистка после тестов
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def client(app):
    """Тестовый клиент."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """Тестовый runner для CLI команд."""
    return app.test_cli_runner()

def hash_password(password):
    """Хэширование пароля для тестов."""
    return hashlib.sha256(password.encode()).hexdigest()

class AuthActions:
    """Вспомогательный класс для аутентификации."""
    def __init__(self, client):
        self._client = client
    
    def login(self, login='test_client', password='test123'):
        return self._client.post('/login', data={
            'login': login,
            'password': password
        })
    
    def logout(self):
        return self._client.get('/logout')

@pytest.fixture
def auth(client):
    return AuthActions(client)