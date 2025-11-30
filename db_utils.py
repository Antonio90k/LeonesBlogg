import sqlite3
import os

def get_connection(db_path):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn):
    cur = conn.cursor()

    # Usuarios
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            profile_image TEXT,
            bio TEXT DEFAULT '',
            link TEXT DEFAULT '',
            restricted_until TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Posts
    cur.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            image_filename TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Comentarios (con respuestas)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            parent_comment_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Reacciones
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reactions (
            user_id INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            reaction_type TEXT NOT NULL,
            PRIMARY KEY (user_id, post_id)
        )
    """)

    # Log de eventos
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Hashtags
    cur.execute("""
        CREATE TABLE IF NOT EXISTS post_tags (
            post_id INTEGER NOT NULL,
            tag TEXT NOT NULL,
            PRIMARY KEY (post_id, tag)
        )
    """)

    # Posts guardados
    cur.execute("""
        CREATE TABLE IF NOT EXISTS saved_posts (
            user_id INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, post_id)
        )
    """)

    # Reportes
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_user_id INTEGER,
            post_id INTEGER,
            comment_id INTEGER,
            reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Notificaciones
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            data TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            read INTEGER DEFAULT 0
        )
    """)

    conn.commit()
