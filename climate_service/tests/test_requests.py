# tests/test_requests.py
import pytest

def test_index_page(client, auth):
    """Тест главной страницы."""
    auth.login('test_client', 'test123')
    response = client.get('/')
    assert response.status_code == 200
    assert b'Заявки на ремонт' in response.data
    assert b'Кондиционер' in response.data

def test_create_request_get(client, auth):
    """Тест страницы создания заявки (GET)."""
    auth.login('test_client', 'test123')
    response = client.get('/request/create')
    assert response.status_code == 200
    assert b'Создание новой заявки' in response.data
    assert b'Тип оборудования:' in response.data

def test_create_request_post(client, auth):
    """Тест создания заявки (POST)."""
    auth.login('test_client', 'test123')
    response = client.post('/request/create', data={
        'equipment_type': 'Тестовый тип',
        'equipment_model': 'Тестовая модель',
        'problem_description': 'Тестовое описание проблемы'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Заявка успешно создана' in response.data

def test_request_detail(client, auth):
    """Тест детальной страницы заявки."""
    auth.login('test_client', 'test123')
    response = client.get('/request/1000')
    assert response.status_code == 200
    assert b'Кондиционер' in response.data
    assert b'Test Model 1' in response.data

def test_change_status(client, auth):
    """Тест изменения статуса заявки."""
    auth.login('test_operator', 'test123')
    response = client.post('/request/1000/change-status', data={
        'status': 'in_progress'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Статус заявки изменен' in response.data

def test_assign_master(client, auth):
    """Тест назначения мастера."""
    auth.login('test_operator', 'test123')
    response = client.post('/request/1000/assign-master', data={
        'master_id': '101'  # ID тестового специалиста
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Мастер назначен на заявку' in response.data

def test_add_comment(client, auth):
    """Тест добавления комментария."""
    auth.login('test_specialist', 'test123')
    response = client.post('/request/1000/add-comment', data={
        'message': 'Тестовый комментарий'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Комментарий добавлен' in response.data