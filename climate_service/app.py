# app.py - ПОЛНАЯ ВЕРСИЯ С ВСЕМИ ФУНКЦИЯМИ
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, send_file
from database import init_app as init_db, get_db
import hashlib
import os
import io
import qrcode
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'dev-secret-key-change-in-production'

# Инициализация БД
init_db(app)

def hash_password(password):
    """Хэширует пароль с использованием SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

@app.before_request
def load_logged_in_user():
    """Загружает информацию о текущем пользователе."""
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        db = get_db()
        g.user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

def login_required(view):
    """Декоратор для проверки авторизации."""
    from functools import wraps
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def role_required(*required_roles):
    """Декоратор для проверки роли."""
    from functools import wraps
    def decorator(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            if g.user is None:
                return redirect(url_for('login'))
            
            # АДМИН ИМЕЕТ ДОСТУП КО ВСЕМУ
            if g.user['role'] == 'admin':
                return view(**kwargs)
            
            if g.user['role'] not in required_roles:
                flash('Недостаточно прав для доступа к этой странице.', 'danger')
                return redirect(url_for('index'))
            return view(**kwargs)
        return wrapped_view
    return decorator

# --- ОСНОВНЫЕ МАРШРУТЫ ---

@app.route('/')
@login_required
def index():
    """Главная страница - список заявок."""
    db = get_db()
    
    # Если пользователь - клиент, показываем только его заявки
    if g.user['role'] == 'client':
        requests = db.execute('''
            SELECT r.*, u.fio as specialist_fio
            FROM repair_requests r
            LEFT JOIN users u ON r.assigned_specialist_id = u.id
            WHERE r.client_id = ?
            ORDER BY r.created_date DESC
        ''', (g.user['id'],)).fetchall()
    else:
        # Для всех остальных показываем все заявки
        requests = db.execute('''
            SELECT r.*, uc.fio as client_fio, us.fio as specialist_fio
            FROM repair_requests r
            LEFT JOIN users uc ON r.client_id = uc.id
            LEFT JOIN users us ON r.assigned_specialist_id = us.id
            ORDER BY r.created_date DESC
        ''').fetchall()
    
    return render_template('index.html', requests=requests)

@app.route('/login', methods=('GET', 'POST'))
def login():
    """Страница входа в систему."""
    if request.method == 'POST':
        login_input = request.form['login']
        password_input = request.form['password']
        
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE login = ?', (login_input,)
        ).fetchone()
        
        if user is None or user['password_hash'] != hash_password(password_input):
            flash('Неверный логин или пароль.', 'danger')
        else:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Выход из системы."""
    session.clear()
    return redirect(url_for('login'))

@app.route('/request/create', methods=('GET', 'POST'))
@login_required
@role_required('client', 'operator', 'admin')
def create_request():
    """Создание новой заявки."""
    if request.method == 'POST':
        equipment_type = request.form['equipment_type']
        equipment_model = request.form['equipment_model']
        problem_description = request.form['problem_description']
        
        # Для клиента client_id = текущий пользователь
        client_id = g.user['id']
        
        db = get_db()
        db.execute('''
            INSERT INTO repair_requests (client_id, equipment_type, equipment_model, problem_description)
            VALUES (?, ?, ?, ?)
        ''', (client_id, equipment_type, equipment_model, problem_description))
        db.commit()
        
        flash('Заявка успешно создана!', 'success')
        return redirect(url_for('index'))
    
    return render_template('request_create.html')

@app.route('/request/<int:request_id>')
@login_required
def request_detail(request_id):
    """Детальная информация о заявке."""
    db = get_db()
    
    request_data = db.execute('''
        SELECT r.*, uc.fio as client_fio, us.fio as specialist_fio
        FROM repair_requests r
        LEFT JOIN users uc ON r.client_id = uc.id
        LEFT JOIN users us ON r.assigned_specialist_id = us.id
        WHERE r.id = ?
    ''', (request_id,)).fetchone()
    
    if request_data is None:
        flash('Заявка не найдена.', 'danger')
        return redirect(url_for('index'))
    
    # Проверка прав доступа
    if g.user['role'] == 'client' and request_data['client_id'] != g.user['id']:
        flash('У вас нет доступа к этой заявке.', 'danger')
        return redirect(url_for('index'))
    
    # Получаем комментарии
    comments = db.execute('''
        SELECT c.*, u.fio as author_fio
        FROM comments c
        JOIN users u ON c.author_id = u.id
        WHERE c.request_id = ?
        ORDER BY c.created_at DESC
    ''', (request_id,)).fetchall()
    
    # Получаем список мастеров для формы назначения
    masters = db.execute('''
        SELECT id, fio FROM users 
        WHERE role IN ('specialist', 'admin')
        ORDER BY fio
    ''').fetchall()
    
    return render_template('request_detail.html', 
                         request=request_data, 
                         comments=comments,
                         masters=masters)

@app.route('/request/<int:request_id>/change-status', methods=('POST',))
@login_required
@role_required('operator', 'specialist', 'admin', 'manager')
def change_status(request_id):
    """Изменение статуса заявки."""
    new_status = request.form['status']
    db = get_db()
    
    # Получаем текущую заявку
    request_data = db.execute(
        'SELECT * FROM repair_requests WHERE id = ?', (request_id,)
    ).fetchone()
    
    if request_data is None:
        flash('Заявка не найдена.', 'danger')
        return redirect(url_for('index'))
    
    # Проверка прав для специалиста
    if g.user['role'] == 'specialist':
        # Специалист может менять статус только своих заявок
        if request_data['assigned_specialist_id'] != g.user['id']:
            flash('Вы не можете менять статус этой заявки.', 'danger')
            return redirect(url_for('request_detail', request_id=request_id))
    
    # Если статус меняется на "completed", устанавливаем дату завершения
    completion_date = None
    if new_status == 'completed' and request_data['status'] != 'completed':
        completion_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    db.execute('''
        UPDATE repair_requests 
        SET status = ?, completion_date = ?
        WHERE id = ?
    ''', (new_status, completion_date, request_id))
    db.commit()
    
    status_names = {
        'new': 'Новая',
        'in_progress': 'В работе', 
        'waiting_parts': 'Ожидание запчастей',
        'completed': 'Завершена',
        'cancelled': 'Отменена'
    }
    
    flash(f'Статус заявки изменен на "{status_names.get(new_status, new_status)}"', 'success')
    return redirect(url_for('request_detail', request_id=request_id))

@app.route('/request/<int:request_id>/assign-master', methods=('POST',))
@login_required
@role_required('operator', 'admin', 'manager', 'quality_manager')
def assign_master(request_id):
    """Назначение мастера на заявку."""
    master_id = request.form.get('master_id')
    
    if not master_id:
        flash('Выберите мастера.', 'danger')
        return redirect(url_for('request_detail', request_id=request_id))
    
    db = get_db()
    
    # Проверяем, существует ли мастер
    master = db.execute(
        'SELECT * FROM users WHERE id = ? AND role IN ("specialist", "admin")', 
        (master_id,)
    ).fetchone()
    
    if master is None:
        flash('Выбранный мастер не найден.', 'danger')
        return redirect(url_for('request_detail', request_id=request_id))
    
    db.execute('''
        UPDATE repair_requests 
        SET assigned_specialist_id = ?, status = 'in_progress'
        WHERE id = ?
    ''', (master_id, request_id))
    db.commit()
    
    flash(f'Мастер {master["fio"]} назначен на заявку', 'success')
    return redirect(url_for('request_detail', request_id=request_id))

@app.route('/request/<int:request_id>/take', methods=('POST',))
@login_required
@role_required('specialist')
def take_request(request_id):
    """Специалист берет заявку в работу."""
    db = get_db()
    
    db.execute('''
        UPDATE repair_requests 
        SET assigned_specialist_id = ?, status = 'in_progress'
        WHERE id = ? AND (assigned_specialist_id IS NULL OR assigned_specialist_id = ?)
    ''', (g.user['id'], request_id, g.user['id']))
    db.commit()
    
    flash('Вы взяли заявку в работу!', 'success')
    return redirect(url_for('request_detail', request_id=request_id))

@app.route('/request/<int:request_id>/edit', methods=('GET', 'POST'))
@login_required
@role_required('operator', 'specialist', 'admin', 'manager')
def edit_request(request_id):
    """Редактирование заявки."""
    db = get_db()
    
    # Получаем заявку
    request_data = db.execute('''
        SELECT r.*, uc.fio as client_fio
        FROM repair_requests r
        LEFT JOIN users uc ON r.client_id = uc.id
        WHERE r.id = ?
    ''', (request_id,)).fetchone()
    
    if request_data is None:
        flash('Заявка не найдена.', 'danger')
        return redirect(url_for('index'))
    
    # Проверка прав для специалиста
    if g.user['role'] == 'specialist':
        if request_data['assigned_specialist_id'] != g.user['id']:
            flash('Вы не можете редактировать эту заявку.', 'danger')
            return redirect(url_for('request_detail', request_id=request_id))
    
    # Получаем список специалистов для выпадающего списка
    specialists = db.execute('''
        SELECT id, fio FROM users 
        WHERE role IN ('specialist', 'admin')
        ORDER BY fio
    ''').fetchall()
    
    if request.method == 'POST':
        status = request.form['status']
        assigned_specialist_id = request.form.get('assigned_specialist_id') or None
        repair_parts = request.form.get('repair_parts', '')
        
        # Если статус "completed", устанавливаем дату завершения
        completion_date = None
        if status == 'completed' and request_data['status'] != 'completed':
            completion_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        db.execute('''
            UPDATE repair_requests 
            SET status = ?, 
                assigned_specialist_id = ?, 
                repair_parts = ?,
                completion_date = ?
            WHERE id = ?
        ''', (status, assigned_specialist_id, repair_parts, completion_date, request_id))
        db.commit()
        
        flash('Заявка успешно обновлена!', 'success')
        return redirect(url_for('request_detail', request_id=request_id))
    
    return render_template('request_edit.html', 
                         request=request_data, 
                         specialists=specialists)

@app.route('/request/<int:request_id>/add-comment', methods=('POST',))
@login_required
@role_required('specialist', 'operator', 'admin', 'manager', 'quality_manager')
def add_comment(request_id):
    """Добавление комментария к заявке."""
    message = request.form.get('message', '').strip()
    
    if not message:
        flash('Комментарий не может быть пустым.', 'danger')
        return redirect(url_for('request_detail', request_id=request_id))
    
    db = get_db()
    db.execute('''
        INSERT INTO comments (request_id, author_id, message)
        VALUES (?, ?, ?)
    ''', (request_id, g.user['id'], message))
    db.commit()
    
    flash('Комментарий добавлен!', 'success')
    return redirect(url_for('request_detail', request_id=request_id))

@app.route('/users')
@login_required
@role_required('admin', 'operator', 'manager')  
def users():
    """Список пользователей."""
    db = get_db()
    users_list = db.execute('SELECT * FROM users ORDER BY id').fetchall()
    return render_template('users.html', users=users_list)

@app.route('/masters')
@login_required
@role_required('operator', 'admin', 'manager')
def masters():
    """Список мастеров и их загрузка."""
    db = get_db()
    
    # Получаем всех специалистов
    masters_list = db.execute('''
        SELECT u.*, 
               COUNT(r.id) as active_requests,
               SUM(CASE WHEN r.status = 'completed' THEN 1 ELSE 0 END) as completed_requests
        FROM users u
        LEFT JOIN repair_requests r ON u.id = r.assigned_specialist_id 
            AND r.status IN ('new', 'in_progress', 'waiting_parts')
        WHERE u.role IN ('specialist', 'admin')
        GROUP BY u.id
        ORDER BY u.fio
    ''').fetchall()
    
    # Получаем заявки без мастера
    unassigned_requests = db.execute('''
        SELECT COUNT(*) as count 
        FROM repair_requests 
        WHERE assigned_specialist_id IS NULL AND status = 'new'
    ''').fetchone()['count']
    
    return render_template('masters.html', 
                         masters=masters_list, 
                         unassigned_requests=unassigned_requests)

@app.route('/stats')
@login_required
@role_required('admin', 'manager', 'operator')
def stats():
    """Статистика работы."""
    db = get_db()
    
    # Общая статистика
    total_requests = db.execute('SELECT COUNT(*) FROM repair_requests').fetchone()[0]
    completed_requests = db.execute("SELECT COUNT(*) FROM repair_requests WHERE status = 'completed'").fetchone()[0]
    in_progress_requests = db.execute("SELECT COUNT(*) FROM repair_requests WHERE status = 'in_progress'").fetchone()[0]
    
    # Статистика по типам оборудования
    equipment_stats = db.execute('''
        SELECT equipment_type, COUNT(*) as count
        FROM repair_requests
        GROUP BY equipment_type
        ORDER BY count DESC
    ''').fetchall()
    
    # Среднее время выполнения заявок
    avg_time_result = db.execute('''
        SELECT AVG(julianday(completion_date) - julianday(created_date)) as avg_days
        FROM repair_requests 
        WHERE status = 'completed' AND completion_date IS NOT NULL
    ''').fetchone()
    
    avg_days = avg_time_result['avg_days'] if avg_time_result and avg_time_result['avg_days'] else 0
    
    # Статистика по статусам
    status_stats = db.execute('''
        SELECT status, COUNT(*) as count
        FROM repair_requests
        GROUP BY status
    ''').fetchall()
    
    return render_template('stats.html',
                         total_requests=total_requests,
                         completed_requests=completed_requests,
                         in_progress_requests=in_progress_requests,
                         equipment_stats=equipment_stats,
                         status_stats=status_stats,
                         avg_days=round(avg_days, 2) if avg_days else 0)

# --- ФУНКЦИОНАЛ МЕНЕДЖЕРА ПО КАЧЕСТВУ ---

@app.route('/overdue-requests')
@login_required
@role_required('quality_manager', 'admin', 'manager')
def overdue_requests():
    """Просроченные заявки."""
    db = get_db()
    
    # Заявки в работе больше 7 дней
    overdue = db.execute('''
        SELECT r.*, uc.fio as client_fio, us.fio as specialist_fio,
               julianday('now') - julianday(r.created_date) as days_passed
        FROM repair_requests r
        LEFT JOIN users uc ON r.client_id = uc.id
        LEFT JOIN users us ON r.assigned_specialist_id = us.id
        WHERE r.status IN ('in_progress', 'waiting_parts')
        AND julianday('now') - julianday(r.created_date) > 7
        ORDER BY days_passed DESC
    ''').fetchall()
    
    return render_template('overdue_requests.html', requests=overdue)

@app.route('/problem-requests')
@login_required
@role_required('quality_manager', 'specialist', 'operator', 'admin', 'manager')
def problem_requests():
    """Проблемные заявки для консультации."""
    db = get_db()
    
    # Заявки со статусом waiting_parts или с комментариями о проблемах
    problems = db.execute('''
        SELECT r.*, uc.fio as client_fio, us.fio as specialist_fio,
               (SELECT COUNT(*) FROM comments c WHERE c.request_id = r.id) as comment_count
        FROM repair_requests r
        LEFT JOIN users uc ON r.client_id = uc.id
        LEFT JOIN users us ON r.assigned_specialist_id = us.id
        WHERE r.status = 'waiting_parts'
           OR r.id IN (
               SELECT DISTINCT request_id 
               FROM comments 
               WHERE message LIKE '%проблем%' 
                  OR message LIKE '%сложн%' 
                  OR message LIKE '%не могу%'
           )
        ORDER BY r.created_date DESC
    ''').fetchall()
    
    return render_template('problem_requests.html', requests=problems)

@app.route('/request/<int:request_id>/extend-deadline', methods=('GET', 'POST'))
@login_required
@role_required('quality_manager', 'admin')
def extend_deadline(request_id):
    """Продление срока выполнения заявки."""
    db = get_db()
    
    request_data = db.execute('''
        SELECT r.*, uc.fio as client_fio
        FROM repair_requests r
        LEFT JOIN users uc ON r.client_id = uc.id
        WHERE r.id = ?
    ''', (request_id,)).fetchone()
    
    if request_data is None:
        flash('Заявка не найдена.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        extra_days = int(request.form['extra_days'])
        reason = request.form['reason']
        
        # Добавляем комментарий о продлении
        db.execute('''
            INSERT INTO comments (request_id, author_id, message)
            VALUES (?, ?, ?)
        ''', (request_id, g.user['id'], 
              f'Срок выполнения продлен на {extra_days} дней. Причина: {reason}'))
        
        db.commit()
        
        flash(f'Срок заявки продлен на {extra_days} дней', 'success')
        return redirect(url_for('request_detail', request_id=request_id))
    
    return render_template('extend_deadline.html', request=request_data)

@app.route('/request/<int:request_id>/add-specialist', methods=('POST',))
@login_required
@role_required('quality_manager', 'admin', 'manager')
def add_specialist(request_id):
    """Привлечение дополнительного специалиста."""
    specialist_id = request.form.get('specialist_id')
    
    if not specialist_id:
        flash('Выберите специалиста.', 'danger')
        return redirect(url_for('request_detail', request_id=request_id))
    
    db = get_db()
    
    # Проверяем специалиста
    specialist = db.execute(
        'SELECT * FROM users WHERE id = ? AND role IN ("specialist", "admin")', 
        (specialist_id,)
    ).fetchone()
    
    if specialist is None:
        flash('Специалист не найден.', 'danger')
        return redirect(url_for('request_detail', request_id=request_id))
    
    # Добавляем комментарий о привлечении специалиста
    db.execute('''
        INSERT INTO comments (request_id, author_id, message)
        VALUES (?, ?, ?)
    ''', (request_id, g.user['id'], 
          f'Привлечен дополнительный специалист: {specialist["fio"]}'))
    
    # Если у заявки нет основного мастера, назначаем его
    current_master = db.execute(
        'SELECT assigned_specialist_id FROM repair_requests WHERE id = ?',
        (request_id,)
    ).fetchone()
    
    if not current_master['assigned_specialist_id']:
        db.execute('''
            UPDATE repair_requests 
            SET assigned_specialist_id = ?, status = 'in_progress'
            WHERE id = ?
        ''', (specialist_id, request_id))
    
    db.commit()
    
    flash(f'Специалист {specialist["fio"]} привлечен к работе', 'success')
    return redirect(url_for('request_detail', request_id=request_id))

@app.route('/quality-stats')
@login_required
@role_required('quality_manager', 'admin', 'manager')
def quality_stats():
    """Статистика качества работы."""
    db = get_db()
    
    # Среднее время выполнения
    avg_time = db.execute('''
        SELECT AVG(julianday(completion_date) - julianday(created_date)) as avg_days
        FROM repair_requests 
        WHERE status = 'completed' AND completion_date IS NOT NULL
    ''').fetchone()['avg_days'] or 0
    
    # Количество просроченных
    overdue_count = db.execute('''
        SELECT COUNT(*) as count
        FROM repair_requests
        WHERE status IN ('in_progress', 'waiting_parts')
        AND julianday('now') - julianday(created_date) > 7
    ''').fetchone()['count']
    
    # Заявки с проблемами
    problem_count = db.execute('''
        SELECT COUNT(DISTINCT r.id) as count
        FROM repair_requests r
        LEFT JOIN comments c ON r.id = c.request_id
        WHERE r.status = 'waiting_parts'
           OR c.message LIKE '%проблем%' 
           OR c.message LIKE '%сложн%'
    ''').fetchone()['count']
    
    return render_template('quality_stats.html',
                         avg_days=round(avg_time, 2),
                         overdue_count=overdue_count,
                         problem_count=problem_count)

# --- ГЕНЕРАЦИЯ QR-КОДОВ ---

@app.route('/request/<int:request_id>/feedback-qr')
@login_required
@role_required('operator', 'admin', 'quality_manager')
def generate_feedback_qr(request_id):
    """Генерация QR-кода для оценки работы."""
    
    # Ссылка на форму Google (из задания)
    feedback_url = "https://docs.google.com/forms/d/e/1FAIpQLSdhZcExx6LSIXxk0ub55mSu-WIh23WYdGG9HY5EZhLDo7P8eA/viewform?usp=sf_link"
    
    # Добавляем ID заявки в URL для отслеживания
    feedback_url_with_id = f"{feedback_url}&entry.1234567890={request_id}"
    
    # Создаем QR-код
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(feedback_url_with_id)
    qr.make(fit=True)
    
    # Создаем изображение
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Сохраняем в буфер
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    
    return send_file(buf, mimetype='image/png', as_attachment=False, 
                     download_name=f'feedback_qr_{request_id}.png')

@app.route('/request/<int:request_id>/feedback')
@login_required
def feedback_page(request_id):
    """Страница с QR-кодом для оценки."""
    db = get_db()
    
    request_data = db.execute('''
        SELECT r.*, uc.fio as client_fio
        FROM repair_requests r
        LEFT JOIN users uc ON r.client_id = uc.id
        WHERE r.id = ?
    ''', (request_id,)).fetchone()
    
    if request_data is None:
        flash('Заявка не найдена.', 'danger')
        return redirect(url_for('index'))
    
    # Ссылка на форму
    feedback_url = "https://docs.google.com/forms/d/e/1FAIpQLSdhZcExx6LSIXxk0ub55mSu-WIh23WYdGG9HY5EZhLDo7P8eA/viewform?usp=sf_link"
    
    return render_template('feedback.html', 
                         request=request_data, 
                         feedback_url=feedback_url)

# --- ОБРАБОТКА ОШИБОК ---

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# --- ИНИЦИАЛИЗАЦИЯ БД И ТЕСТОВЫХ ДАННЫХ ---

def import_initial_data():
    """Импорт начальных данных."""
    db = get_db()
    
    # Проверяем, есть ли уже пользователи
    if db.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
        # Импортируем пользователей
        users_data = [
            (1, 'Широков Василий Матвеевич', '89210563128', 'login1', hash_password('pass1'), 'admin'),
            (2, 'Кудрявцева Ева Ивановна', '89535078985', 'login2', hash_password('pass2'), 'specialist'),
            (3, 'Гончарова Ульяна Ярославовна', '89210673849', 'login3', hash_password('pass3'), 'specialist'),
            (4, 'Гусева Виктория Данииловна', '89990563748', 'login4', hash_password('pass4'), 'operator'),
            (5, 'Баранов Артём Юрьевич', '89994563847', 'login5', hash_password('pass5'), 'operator'),
            (6, 'Овчинников Фёдор Никитич', '89219567849', 'login6', hash_password('pass6'), 'client'),
            (7, 'Петров Никита Артёмович', '89219567841', 'login7', hash_password('pass7'), 'client'),
            (8, 'Ковалева Софья Владимировна', '89219567842', 'login8', hash_password('pass8'), 'client'),
            (9, 'Кузнецов Сергей Матвеевич', '89219567843', 'login9', hash_password('pass9'), 'client'),
            (10, 'Беспалова Екатерина Даниэльевна', '89219567844', 'login10', hash_password('pass10'), 'specialist'),
            (11, 'Смирнова Анна Петровна', '89215556677', 'quality1', hash_password('quality123'), 'quality_manager')
        ]
        
        for user in users_data:
            try:
                db.execute('''
                    INSERT INTO users (id, fio, phone, login, password_hash, role)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', user)
            except:
                continue
        
        # Импортируем тестовые заявки
        try:
            test_requests = [
                (1, '2023-06-06', 7, 'Кондиционер', 'TCL TAC-12CHSA/TPG-W белый', 'Не охлаждает воздух', 'in_progress', None, None, 2),
                (2, '2023-05-05', 8, 'Кондиционер', 'Electrolux EACS/I-09HAT/N3_21Y белый', 'Выключается сам по себе', 'in_progress', None, None, 3),
                (3, '2022-07-07', 9, 'Увлажнитель воздуха', 'Xiaomi Smart Humidifier 2', 'Пар имеет неприятный запах', 'completed', '2023-01-01', 'Заменен фильтр', 3),
                (4, '2023-08-02', 8, 'Увлажнитель воздуха', 'Polaris PUH 2300 WIFI IQ Home', 'Увлажнитель воздуха продолжает работать при предельном снижении уровня воды', 'new', None, None, None),
                (5, '2023-08-02', 9, 'Сушилка для рук', 'Ballu BAHD-1250', 'Не работает', 'new', None, None, None)
            ]
            
            for req in test_requests:
                db.execute('''
                    INSERT OR IGNORE INTO repair_requests (id, created_date, client_id, equipment_type, equipment_model, problem_description, status, completion_date, repair_parts, assigned_specialist_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', req)
            
            # Импортируем тестовые комментарии
            test_comments = [
                (1, 'Всё сделаем! Заказ принят в работу.', 2, 1),
                (2, 'Проблема известная, уже работаем над ней.', 3, 2),
                (3, 'Ремонт завершен, можно забирать оборудование.', 3, 3)
            ]
            
            for comment in test_comments:
                db.execute('''
                    INSERT OR IGNORE INTO comments (id, message, author_id, request_id)
                    VALUES (?, ?, ?, ?)
                ''', comment)
                
        except Exception as e:
            print(f"Ошибка при импорте заявок: {e}")
        
        db.commit()
        print("Тестовые данные успешно импортированы!")

if __name__ == '__main__':
    with app.app_context():
        # Создаем базу данных и таблицы
        db = get_db()
        try:
            with open('schema.sql', 'r', encoding='utf-8') as f:
                db.executescript(f.read())
        except Exception as e:
            print(f"Ошибка при чтении schema.sql: {e}")
            # Если файл не найден, создаем таблицы напрямую
            db.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fio TEXT NOT NULL,
                    phone TEXT NOT NULL,
                    login TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS repair_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    client_id INTEGER NOT NULL,
                    equipment_type TEXT NOT NULL,
                    equipment_model TEXT NOT NULL,
                    problem_description TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new',
                    assigned_specialist_id INTEGER,
                    completion_date TIMESTAMP,
                    repair_parts TEXT,
                    FOREIGN KEY (client_id) REFERENCES users (id),
                    FOREIGN KEY (assigned_specialist_id) REFERENCES users (id)
                );
                
                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER NOT NULL,
                    author_id INTEGER NOT NULL,
                    message TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (request_id) REFERENCES repair_requests (id) ON DELETE CASCADE,
                    FOREIGN KEY (author_id) REFERENCES users (id)
                );
            ''')
            db.commit()
        
        # Импортируем начальные данные
        import_initial_data()
    
    print("=" * 60)
    print("СИСТЕМА УЧЕТА ЗАЯВОК НА РЕМОНТ КЛИМАТИЧЕСКОГО ОБОРУДОВАНИЯ")
    print("=" * 60)
    print("✅ База данных инициализирована")
    print("✅ Тестовые данные загружены")
    print("\n📱 ТЕСТОВЫЕ УЧЕТНЫЕ ЗАПИСИ:")
    print("  👨‍💼 АДМИНИСТРАТОР (полный доступ):     login1 / pass1")
    print("  👩‍💼 Оператор:                         login4 / pass4")
    print("  👨‍🔧 Специалист:                       login2 / pass2")
    print("  👨‍🔧 Специалист 2:                     login3 / pass3")
    print("  👤 Клиент:                            login6 / pass6")
    print("  📊 Менеджер по качеству:              quality1 / quality123")
    print("\n🌐 Откройте браузер и перейдите по адресу: http://localhost:5000")
    print("=" * 60)
    
    app.run(debug=True, port=5000, host='0.0.0.0')