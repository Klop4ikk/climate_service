# tests/test_auth.py
import pytest

def test_login_page(client):
    """Тест страницы входа."""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Вход в систему' in response.data
    assert b'Логин:' in response.data
    assert b'Пароль:' in response.data

def test_successful_login(client, auth):
    """Тест успешного входа."""
    response = auth.login('test_client', 'test123')
    assert response.status_code == 302  # Редирект
    assert '/login' not in response.headers['Location']

def test_failed_login(client):
    """Тест неудачного входа."""
    response = client.post('/login', data={
        'login': 'wrong',
        'password': 'wrong'
    })
    assert response.status_code == 200
    assert b'Неверный логин или пароль' in response.data

def test_logout(client, auth):
    """Тест выхода из системы."""
    auth.login('test_client', 'test123')
    response = auth.logout()
    assert response.status_code == 302
    assert response.headers['Location'] == '/login'

def test_protected_pages_require_login(client):
    """Тест что защищенные страницы требуют авторизации."""
    pages = ['/', '/users', '/stats', '/request/create']
    
    for page in pages:
        response = client.get(page, follow_redirects=True)
        assert response.status_code == 200
        assert b'Вход в систему' in response.data

def test_role_based_access(client, auth):
    """Тест доступа по ролям."""
    # Клиент не может видеть пользователей
    auth.login('test_client', 'test123')
    response = client.get('/users', follow_redirects=True)
    assert b'Недостаточно прав' in response.data
    
    # Оператор может видеть пользователей
    auth.login('test_operator', 'test123')
    response = client.get('/users')
    assert response.status_code == 200
    assert b'Тест Клиент' in response.data