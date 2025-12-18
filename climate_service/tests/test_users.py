# tests/test_users.py
import pytest

def test_users_page_access(client, auth):
    """Тест доступа к странице пользователей."""
    # Клиент не имеет доступа
    auth.login('test_client', 'test123')
    response = client.get('/users', follow_redirects=True)
    assert b'Недостаточно прав' in response.data
    
    # Оператор имеет доступ
    auth.login('test_operator', 'test123')
    response = client.get('/users')
    assert response.status_code == 200
    assert b'Список пользователей' in response.data

def test_users_list_content(client, auth):
    """Тест содержимого списка пользователей."""
    auth.login('test_operator', 'test123')
    response = client.get('/users')
    
    assert b'Тест Клиент' in response.data
    assert b'Тест Специалист' in response.data
    assert b'Тест Оператор' in response.data
    assert b'client' in response.data
    assert b'specialist' in response.data
    assert b'operator' in response.data

def test_masters_page(client, auth):
    """Тест страницы мастеров."""
    auth.login('test_operator', 'test123')
    response = client.get('/masters')
    
    assert response.status_code == 200
    assert b'Управление мастерами' in response.data
    assert b'Тест Специалист' in response.data
    assert b'Активные заявки' in response.data