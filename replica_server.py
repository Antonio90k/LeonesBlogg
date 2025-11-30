from flask import Flask, request, jsonify
import sqlite3
import json
import os

from db_utils import get_connection, init_db

REPLICA_NAME = os.environ.get("REPLICA_NAME", "Replica")
DB_PATH = os.path.join("db", f"{REPLICA_NAME}.db")

app = Flask(__name__)

conn = get_connection(DB_PATH)
init_db(conn)


def apply_event(event_type, payload):
    cur = conn.cursor()

    if event_type == "CREATE_POST":
        cur.execute(
            """
            INSERT OR IGNORE INTO posts (id, user_id, title, content, image_filename, created_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                payload["post_id"],
                payload["user_id"],
                payload["title"],
                payload["content"],
                payload.get("image_filename"),
            )
        )
        conn.commit()

    elif event_type == "REACT_POST":
        cur.execute(
            """
            INSERT INTO reactions (user_id, post_id, reaction_type)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, post_id)
            DO UPDATE SET reaction_type = excluded.reaction_type
            """,
            (
                payload["user_id"],
                payload["post_id"],
                payload["reaction_type"],
            )
        )
        conn.commit()

    elif event_type == "COMMENT_POST":
        cur.execute(
            """
            INSERT OR IGNORE INTO comments (id, user_id, post_id, content, parent_comment_id, created_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                payload["comment_id"],
                payload["user_id"],
                payload["post_id"],
                payload["content"],
                payload.get("parent_comment_id"),
            )
        )
        conn.commit()

    elif event_type == "UPDATE_POST":
        cur.execute(
            """
            UPDATE posts
            SET title = ?, content = ?, image_filename = ?
            WHERE id = ?
            """,
            (
                payload["title"],
                payload["content"],
                payload.get("image_filename"),
                payload["post_id"],
            )
        )
        conn.commit()

    elif event_type == "DELETE_POST":
        pid = payload["post_id"]
        cur.execute("DELETE FROM posts WHERE id = ?", (pid,))
        cur.execute("DELETE FROM reactions WHERE post_id = ?", (pid,))
        cur.execute("DELETE FROM comments WHERE post_id = ?", (pid,))
        conn.commit()

    else:
        print(f"[{REPLICA_NAME}] Evento no reconocido:", event_type)


@app.route("/replicate", methods=["POST"])
def replicate():
    data = request.get_json()
    if not data:
        return "No JSON", 400

    event_type = data.get("event_type")
    payload = data.get("payload")

    if not event_type or not payload:
        return "JSON incompleto", 400

    apply_event(event_type, payload)
    return jsonify({"ok": True})


@app.route("/")
def home():
    return f"Replica activa: {REPLICA_NAME}", 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"[{REPLICA_NAME}] Iniciando en puerto {port}...")
    app.run(host="0.0.0.0", port=port)
