-- schema.sql для SQLite
PRAGMA foreign_keys = ON;

-- Удаляем таблицы если они существуют
DROP TABLE IF EXISTS comments;
DROP TABLE IF EXISTS repair_requests;
DROP TABLE IF EXISTS users;

-- Создаем таблицу пользователей
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fio TEXT NOT NULL,
    phone TEXT NOT NULL,
    login TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('client', 'specialist', 'operator', 'manager', 'quality_manager', 'admin'))
);

-- Создаем таблицу заявок
CREATE TABLE repair_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client_id INTEGER NOT NULL,
    equipment_type TEXT NOT NULL,
    equipment_model TEXT NOT NULL,
    problem_description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new', 'in_progress', 'waiting_parts', 'completed', 'cancelled')),
    assigned_specialist_id INTEGER,
    completion_date TIMESTAMP,
    repair_parts TEXT,
    FOREIGN KEY (client_id) REFERENCES users (id),
    FOREIGN KEY (assigned_specialist_id) REFERENCES users (id)
);

-- Создаем таблицу комментариев
CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    author_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES repair_requests (id) ON DELETE CASCADE,
    FOREIGN KEY (author_id) REFERENCES users (id)
);

-- Создаем индексы для ускорения поиска
CREATE INDEX idx_repair_requests_client_id ON repair_requests(client_id);
CREATE INDEX idx_repair_requests_status ON repair_requests(status);
CREATE INDEX idx_repair_requests_specialist_id ON repair_requests(assigned_specialist_id);
CREATE INDEX idx_comments_request_id ON comments(request_id);

-- Создаем таблицу для отслеживания продлений сроков (опционально)
CREATE TABLE IF NOT EXISTS deadline_extensions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    extended_by INTEGER NOT NULL,
    extra_days INTEGER NOT NULL,
    reason TEXT,
    extended_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES repair_requests (id),
    FOREIGN KEY (extended_by) REFERENCES users (id)
);