# database.py
import sqlite3
from flask import g
import os

DATABASE = os.path.join(os.path.dirname(__file__), 'instance', 'climate.db')

def get_db():
    """Возвращает соединение с базой данных."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Закрывает соединение с БД."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Инициализирует БД, создает таблицы."""
    db = get_db()
    with open('schema.sql', 'r', encoding='utf-8') as f:
        db.executescript(f.read())
    db.commit()

def init_app(app):
    """Регистрирует функции для работы с БД в приложении Flask."""
    app.teardown_appcontext(close_db)