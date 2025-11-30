from flask import Flask, request, redirect, render_template, session, url_for, jsonify
import json
import requests
import os
from datetime import datetime, timedelta
from collections import defaultdict
from markupsafe import Markup, escape
import re

from db_utils import get_connection, init_db
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# 🔐 Clave secreta para sesiones
app.secret_key = "Lenovo"

# Rutas base
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Base de datos local (SQLite)
DB_DIR = os.path.join(BASE_DIR, "db")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, "primary.db")

# Carpetas para archivos subidos
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
AVATAR_FOLDER = os.path.join(BASE_DIR, "static", "avatars")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(AVATAR_FOLDER, exist_ok=True)

# Réplicas (si las usas)
REPLICAS = [
    "http://localhost:5001",
    "http://localhost:5002",
]

# IPs desde las que se permite usar funciones de administrador
ADMIN_IPS = {
    "10.60.1.211",  # tu IP de admin (WiFi actual)
    "127.0.0.1",    # localhost
}

# Avatar por defecto
DEFAULT_AVATAR_URL = "https://i.pinimg.com/236x/d4/74/1c/d4741cb779ddec6509ca1ae0cb137a7d.jpg"

conn = get_connection(DB_PATH)
init_db(conn)

# ================== CONFIG / HELPERS BÁSICOS ==================

last_action_times = defaultdict(dict)  # last_action_times[user_id][action_name] = datetime

# Archivos permitidos
ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}
ALLOWED_VIDEO_EXTENSIONS = {"mp4", "webm", "ogg"}
ALLOWED_UPLOAD_EXTENSIONS = ALLOWED_IMAGE_EXTENSIONS | ALLOWED_VIDEO_EXTENSIONS



def allowed_image(filename):
    """Solo para avatares (imágenes)."""
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_IMAGE_EXTENSIONS


def allowed_upload(filename):
    """Para posts: imágenes o videos."""
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_UPLOAD_EXTENSIONS


def current_user():
    if "user_id" not in session:
        return None
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    row = cur.fetchone()
    return dict(row) if row else None


def is_admin_allowed():
    user = current_user()
    if not user or user.get("role") != "admin":
        return False
    client_ip = request.remote_addr
    return client_ip in ADMIN_IPS


def is_restricted(user):
    if not user:
        return False
    ru = user.get("restricted_until")
    if not ru:
        return False
    try:
        until = datetime.fromisoformat(ru)
    except Exception:
        return False
    return datetime.utcnow() < until


def enforce_rate_limit(user_id, action_name, min_interval_seconds=1):
    now = datetime.utcnow()
    user_times = last_action_times[user_id]
    last = user_times.get(action_name)
    if last and (now - last).total_seconds() < min_interval_seconds:
        return False
    user_times[action_name] = now
    return True


def log_event(event_type, payload_dict):
    cur = conn.cursor()
    payload_json = json.dumps(payload_dict)
    cur.execute(
        "INSERT INTO events_log (event_type, payload) VALUES (?, ?)",
        (event_type, payload_json)
    )
    conn.commit()
    event_id = cur.lastrowid
    return event_id, payload_json


def replicate_event(event_id, event_type, payload_json):
    body = {
        "event_id": event_id,
        "event_type": event_type,
        "payload": json.loads(payload_json),
    }
    for replica in REPLICAS:
        try:
            url = f"{replica}/replicate"
            requests.post(url, json=body, timeout=1)
        except Exception:
            # si la réplica no responde, se ignora (eventual consistency)
            pass


def extract_hashtags(text):
    return re.findall(r"#(\w+)", text or "")


def update_post_tags(post_id, content):
    tags = extract_hashtags(content)
    cur = conn.cursor()
    cur.execute("DELETE FROM post_tags WHERE post_id = ?", (post_id,))
    for t in tags:
        cur.execute(
            "INSERT OR IGNORE INTO post_tags (post_id, tag) VALUES (?, ?)",
            (post_id, t.lower())
        )
    conn.commit()


def create_notification(user_id, ntype, data_dict):
    if not user_id:
        return
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO notifications (user_id, type, data) VALUES (?, ?, ?)",
        (user_id, ntype, json.dumps(data_dict))
    )
    conn.commit()


def linkify_mentions(text):
    if not text:
        return ""

    def _repl(match):
        username = match.group(1)
        url = url_for("profile", username=username)
        return f'@<a href="{escape(url)}">{escape(username)}</a>'

    escaped = escape(text)
    pattern = re.compile(r"@(\w+)")
    result = pattern.sub(lambda m: Markup(_repl(m)), escaped)
    return Markup(result)


app.jinja_env.filters["linkify_mentions"] = linkify_mentions


@app.context_processor
def inject_globals():
    user = current_user()
    notif_count = 0
    if user:
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read = 0",
            (user["id"],)
        )
        notif_count = cur.fetchone()[0]
    return {
        "notifications_count": notif_count,
        "DEFAULT_AVATAR_URL": DEFAULT_AVATAR_URL
    }


# ================== ADMIN POR DEFECTO ==================

def ensure_default_admin():
    """Crea o asegura el usuario admin / admin123."""
    cur = conn.cursor()
    cur.execute("SELECT id, username, role FROM users WHERE username = ?", ("admin",))
    row = cur.fetchone()

    if row:
        if row["role"] != "admin":
            cur.execute(
                "UPDATE users SET role = 'admin' WHERE id = ?",
                (row["id"],)
            )
            conn.commit()
            print(f"[INFO] Usuario existente '{row['username']}' promovido a admin.")
        else:
            print(f"[INFO] Usuario admin existente: {row['username']}")
        return

    password = "admin123"
    cur.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
        ("admin", generate_password_hash(password))
    )
    conn.commit()
    print("[INFO] Usuario administrador creado:")
    print("   usuario: admin")
    print("   contraseña: admin123")


ensure_default_admin()

# ================== RUTAS PRINCIPALES ==================


@app.route("/")
def index():
    cur = conn.cursor()
    cur.execute("""
        SELECT p.id, p.title, p.content, p.image_filename, p.created_at,
               u.username, u.profile_image AS user_profile_image
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    """)
    posts = [dict(row) for row in cur.fetchall()]

    # reacciones y comentarios por post
    for p in posts:
        cur.execute(
            "SELECT reaction_type, COUNT(*) AS c FROM reactions WHERE post_id = ? GROUP BY reaction_type",
            (p["id"],)
        )
        reactions = {r["reaction_type"]: r["c"] for r in cur.fetchall()}
        p["reactions_by_type"] = reactions

        cur.execute(
            "SELECT c.id, c.content, c.created_at, c.parent_comment_id, "
            "u.username, u.profile_image AS user_profile_image "
            "FROM comments c "
            "JOIN users u ON c.user_id = u.id "
            "WHERE c.post_id = ? "
            "ORDER BY c.created_at ASC",
            (p["id"],)
        )
        p["comments"] = [dict(row) for row in cur.fetchall()]

    cur.execute("SELECT MAX(id) FROM events_log")
    row = cur.fetchone()
    last_event_id = row[0] if row and row[0] is not None else 0

    user = current_user()
    return render_template(
        "index.html",
        posts=posts,
        user=user,
        admin_allowed=is_admin_allowed(),
        restricted=is_restricted(user),
        last_event_id=last_event_id
    )


@app.route("/posts/<int:post_id>", methods=["GET"])
def view_post(post_id):
    cur = conn.cursor()
    cur.execute("""
        SELECT p.id, p.title, p.content, p.image_filename, p.created_at,
               u.username, u.profile_image AS user_profile_image
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    """, (post_id,))
    row = cur.fetchone()
    if not row:
        # mini vista de "post no encontrado"
        return render_template("post_not_found.html", post_id=post_id), 404

    post = dict(row)

    cur.execute(
        "SELECT reaction_type, COUNT(*) AS c FROM reactions WHERE post_id = ? GROUP BY reaction_type",
        (post_id,)
    )
    post["reactions_by_type"] = {r["reaction_type"]: r["c"] for r in cur.fetchall()}

    cur.execute(
        "SELECT c.id, c.content, c.created_at, c.parent_comment_id, "
        "u.username, u.profile_image AS user_profile_image "
        "FROM comments c "
        "JOIN users u ON c.user_id = u.id "
        "WHERE c.post_id = ? "
        "ORDER BY c.created_at ASC",
        (post_id,)
    )
    post["comments"] = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT MAX(id) FROM events_log")
    row_ev = cur.fetchone()
    last_event_id = row_ev[0] if row_ev and row_ev[0] is not None else 0

    user = current_user()
    return render_template(
        "index.html",
        posts=[post],
        user=user,
        admin_allowed=is_admin_allowed(),
        restricted=is_restricted(user),
        last_event_id=last_event_id
    )

# ================== AUTH ==================


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        if not username or not password:
            return render_template("register.html", error="Completa todos los campos.")

        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )
            conn.commit()
            return redirect(url_for("login"))
        except Exception:
            return render_template("register.html", error="Ese usuario ya existe.")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()

        if row and check_password_hash(row["password_hash"], password):
            session["user_id"] = row["id"]
            return redirect(url_for("index"))

        return render_template("login.html", error="Usuario o contraseña incorrectos.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ================== POSTS / REACCIONES / COMENTARIOS ==================


@app.route("/posts", methods=["POST"])
def create_post():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    if is_restricted(user):
        return "Estás restringido, no puedes publicar por ahora.", 403

    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()

    # Rate limit
    if not enforce_rate_limit(user["id"], "create_post", min_interval_seconds=5):
        return "Estás publicando demasiado rápido, intenta de nuevo en unos segundos.", 429

    # === múltiples archivos ===
    uploaded_files = request.files.getlist("image")  # name="image"
    filenames = []

    for f in uploaded_files:
        if not f or not f.filename:
            continue
        if not allowed_upload(f.filename):
            continue
        safe_name = secure_filename(f.filename)
        path = os.path.join(UPLOAD_FOLDER, safe_name)
        f.save(path)
        filenames.append(safe_name)

    # Guardamos todos los nombres en un solo campo separados por "||"
    media_field = "||".join(filenames) if filenames else None

    # Si NO hay texto NI archivos, no publicamos nada
    if not title and not content and not media_field:
        return redirect(url_for("index"))

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO posts (user_id, title, content, image_filename) VALUES (?, ?, ?, ?)",
        (user["id"], title, content, media_field)
    )
    conn.commit()
    post_id = cur.lastrowid

    update_post_tags(post_id, content)

    event_id, payload_json = log_event("CREATE_POST", {
        "post_id": post_id,
        "user_id": user["id"],
        "title": title,
        "content": content,
        "image_filename": media_field,
    })
    replicate_event(event_id, "CREATE_POST", payload_json)

    return redirect(url_for("profile", username=user["username"]))


@app.route("/posts/<int:post_id>/react", methods=["POST"])
def react_post(post_id):
    user = current_user()
    if not user:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "login required"}), 401
        return redirect(url_for("login"))

    if is_restricted(user):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "restricted", "until": user.get("restricted_until")}), 403
        return "Estás restringido, no puedes reaccionar.", 403

    reaction_type = request.form.get("reaction_type", "like").strip() or "like"

    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO reactions (user_id, post_id, reaction_type)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, post_id) DO UPDATE SET reaction_type = excluded.reaction_type
        """,
        (user["id"], post_id, reaction_type)
    )
    conn.commit()

    cur.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,))
    post_row = cur.fetchone()
    if post_row:
        post_owner_id = post_row["user_id"]
        if post_owner_id != user["id"]:
            create_notification(post_owner_id, "reaction", {
                "from_user": user["username"],
                "post_id": post_id,
                "reaction_type": reaction_type
            })

    event_id, payload_json = log_event("REACT_POST", {
        "post_id": post_id,
        "user_id": user["id"],
        "reaction_type": reaction_type,
    })
    replicate_event(event_id, "REACT_POST", payload_json)

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        cur.execute(
            "SELECT reaction_type, COUNT(*) AS c FROM reactions WHERE post_id = ? GROUP BY reaction_type",
            (post_id,)
        )
        reactions = {r["reaction_type"]: r["c"] for r in cur.fetchall()}
        cur.execute("SELECT COUNT(*) FROM comments WHERE post_id = ?", (post_id,))
        comments_count = cur.fetchone()[0]
        return jsonify({
            "ok": True,
            "post_id": post_id,
            "reactions": reactions,
            "comments_count": comments_count
        })

    return redirect(url_for("index"))


@app.route("/posts/<int:post_id>/comment", methods=["POST"])
def comment_post(post_id):
    user = current_user()
    if not user:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "login required"}), 401
        return redirect(url_for("login"))

    if is_restricted(user):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "restricted", "until": user.get("restricted_until")}), 403
        return "Estás restringido, no puedes comentar.", 403

    content = request.form["content"].strip()
    parent_comment_id_raw = request.form.get("parent_comment_id", "").strip()
    parent_comment_id = int(parent_comment_id_raw) if parent_comment_id_raw else None

    if not content:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "empty"}), 400
        return redirect(url_for("index"))

    if not enforce_rate_limit(user["id"], "comment", min_interval_seconds=1):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": False, "error": "too_fast"}), 429
        return "Comentas demasiado rápido, intenta de nuevo en unos segundos.", 429

    cur = conn.cursor()
    cur.execute(
        "INSERT INTO comments (user_id, post_id, content, parent_comment_id) VALUES (?, ?, ?, ?)",
        (user["id"], post_id, content, parent_comment_id)
    )
    conn.commit()
    comment_id = cur.lastrowid

    cur.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,))
    post_row = cur.fetchone()
    post_owner_id = post_row["user_id"] if post_row else None

    if parent_comment_id:
        cur.execute("SELECT user_id FROM comments WHERE id = ?", (parent_comment_id,))
        parent_row = cur.fetchone()
        parent_owner_id = parent_row["user_id"] if parent_row else None
    else:
        parent_owner_id = None

    if parent_owner_id and parent_owner_id != user["id"]:
        create_notification(parent_owner_id, "reply", {
            "from_user": user["username"],
            "post_id": post_id,
            "comment_id": comment_id,
            "excerpt": content[:80]
        })
    elif post_owner_id and post_owner_id != user["id"]:
        create_notification(post_owner_id, "comment", {
            "from_user": user["username"],
            "post_id": post_id,
            "comment_id": comment_id,
            "excerpt": content[:80]
        })

    event_id, payload_json = log_event("COMMENT_POST", {
        "comment_id": comment_id,
        "post_id": post_id,
        "user_id": user["id"],
        "content": content,
        "parent_comment_id": parent_comment_id,
    })
    replicate_event(event_id, "COMMENT_POST", payload_json)

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        cur.execute(
            "SELECT c.content, c.created_at, c.parent_comment_id, "
            "u.username, u.profile_image "
            "FROM comments c JOIN users u ON c.user_id = u.id "
            "WHERE c.id = ?",
            (comment_id,)
        )
        row = cur.fetchone()
        cur.execute("SELECT COUNT(*) FROM comments WHERE post_id = ?", (post_id,))
        comments_count = cur.fetchone()[0]
        return jsonify({
            "ok": True,
            "post_id": post_id,
            "comment": {
                "id": comment_id,
                "username": row["username"],
                "content": row["content"],
                "created_at": row["created_at"],
                "parent_comment_id": row["parent_comment_id"],
                "profile_image": row["profile_image"]
            },
            "comments_count": comments_count
        })

    return redirect(url_for("index"))


@app.route("/api/comments/<int:comment_id>")
def get_comment(comment_id):
    cur = conn.cursor()
    cur.execute(
        "SELECT c.id, c.user_id, c.post_id, c.content, c.parent_comment_id, c.created_at, "
        "u.username, u.profile_image "
        "FROM comments c JOIN users u ON c.user_id = u.id "
        "WHERE c.id = ?",
        (comment_id,)
    )
    row = cur.fetchone()
    if not row:
        return jsonify({"ok": False, "error": "not_found"}), 404

    c = dict(row)
    return jsonify({
        "ok": True,
        "comment": {
            "id": c["id"],
            "user_id": c["user_id"],
            "post_id": c["post_id"],
            "content": c["content"],
            "parent_comment_id": c["parent_comment_id"],
            "created_at": c["created_at"],
            "username": c["username"],
            "profile_image": c["profile_image"]
        }
    })


@app.route("/admin/posts/<int:post_id>/delete", methods=["POST"])
def delete_post(post_id):
    if not is_admin_allowed():
        return "No autorizado (fuera de la red permitida o no eres admin)", 403

    cur = conn.cursor()
    cur.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    cur.execute("DELETE FROM reactions WHERE post_id = ?", (post_id,))
    cur.execute("DELETE FROM comments WHERE post_id = ?", (post_id,))
    conn.commit()

    event_id, payload_json = log_event("DELETE_POST", {"post_id": post_id})
    replicate_event(event_id, "DELETE_POST", payload_json)
    return redirect(url_for("index"))


@app.route("/user/posts/<int:post_id>/edit", methods=["GET", "POST"])
def edit_own_post(post_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    cur = conn.cursor()
    cur.execute("SELECT * FROM posts WHERE id = ?", (post_id,))
    row = cur.fetchone()
    if not row:
        return "Post no encontrado", 404

    post = dict(row)
    if post["user_id"] != user["id"]:
        return "No autorizado", 403

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()

        if not enforce_rate_limit(user["id"], "edit_post", min_interval_seconds=3):
            return "Editas demasiado rápido, intenta de nuevo en unos segundos.", 429

        # Nuevos archivos (multi)
        uploaded_files = request.files.getlist("image")
        filenames = []

        for f in uploaded_files:
            if not f or not f.filename:
                continue
            if not allowed_upload(f.filename):
                continue
            safe_name = secure_filename(f.filename)
            path = os.path.join(UPLOAD_FOLDER, safe_name)
            f.save(path)
            filenames.append(safe_name)

        if filenames:
            media_field = "||".join(filenames)
        else:
            # conservar lo que ya tenía
            media_field = post["image_filename"]

        # evitar dejar todo vacío
        if not title and not content and not media_field:
            return render_template(
                "edit_post.html",
                post=post,
                error="No puedes dejar la publicación completamente vacía.",
                user=user,
                admin_allowed=is_admin_allowed()
            )

        cur.execute(
            "UPDATE posts SET title = ?, content = ?, image_filename = ? WHERE id = ?",
            (title, content, media_field, post_id)
        )
        conn.commit()

        update_post_tags(post_id, content)

        event_id, payload_json = log_event("UPDATE_POST", {
            "post_id": post_id,
            "title": title,
            "content": content,
            "image_filename": media_field,
        })
        replicate_event(event_id, "UPDATE_POST", payload_json)

        return redirect(url_for("profile", username=user["username"]))

    # GET
    return render_template(
        "edit_post.html",
        post=post,
        user=user,
        admin_allowed=is_admin_allowed()
    )

@app.route("/user/posts/<int:post_id>/delete", methods=["POST"])
def delete_own_post(post_id):
    """
    Borrado de posts desde el perfil del propio usuario.
    """
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    cur = conn.cursor()
    cur.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,))
    row = cur.fetchone()
    if not row:
        return "Post no encontrado", 404

    if row["user_id"] != user["id"]:
        return "No autorizado", 403

    cur.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    cur.execute("DELETE FROM reactions WHERE post_id = ?", (post_id,))
    cur.execute("DELETE FROM comments WHERE post_id = ?", (post_id,))
    conn.commit()

    event_id, payload_json = log_event("DELETE_POST", {"post_id": post_id})
    replicate_event(event_id, "DELETE_POST", payload_json)

    return redirect(url_for("profile", username=user["username"]))

# ================== PERFIL ==================


@app.route("/profile/<username>")
def profile(username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    if not user_row:
        return "Usuario no encontrado", 404
    profile_user = dict(user_row)

    # Posts del usuario, con username y avatar para que el template sea igual que en index
    cur.execute("""
        SELECT p.id, p.title, p.content, p.image_filename, p.created_at,
               u.username, u.profile_image AS user_profile_image
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.user_id = ?
        ORDER BY p.created_at DESC
    """, (profile_user["id"],))
    posts = [dict(row) for row in cur.fetchall()]

    # Añadimos reacciones y comentarios a cada post
    for p in posts:
        cur.execute(
            "SELECT reaction_type, COUNT(*) AS c FROM reactions WHERE post_id = ? GROUP BY reaction_type",
            (p["id"],)
        )
        p["reactions_by_type"] = {r["reaction_type"]: r["c"] for r in cur.fetchall()}

        cur.execute(
            "SELECT c.id, c.content, c.created_at, c.parent_comment_id, "
            "u.username, u.profile_image AS user_profile_image "
            "FROM comments c "
            "JOIN users u ON c.user_id = u.id "
            "WHERE c.post_id = ? "
            "ORDER BY c.created_at ASC",
            (p["id"],)
        )
        p["comments"] = [dict(row) for row in cur.fetchall()]

    saved_posts = []
    user = current_user()
    if user and user["id"] == profile_user["id"]:
        cur.execute("""
            SELECT p.id, p.title, p.content, p.image_filename, p.created_at,
                   u.username, u.profile_image AS user_profile_image
            FROM saved_posts s
            JOIN posts p ON s.post_id = p.id
            JOIN users u ON p.user_id = u.id
            WHERE s.user_id = ?
            ORDER BY s.created_at DESC
        """, (user["id"],))
        saved_posts = [dict(row) for row in cur.fetchall()]

    return render_template(
        "profile.html",
        profile_user=profile_user,
        posts=posts,
        saved_posts=saved_posts,
        user=user,
        admin_allowed=is_admin_allowed(),
        restricted=is_restricted(user)
    )


@app.route("/profile/edit", methods=["GET", "POST"])
def edit_profile():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        bio = request.form.get("bio", "").strip()
        link = request.form.get("link", "").strip()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET bio = ?, link = ? WHERE id = ?",
            (bio, link, user["id"])
        )
        conn.commit()
        return redirect(url_for("profile", username=user["username"]))

    return render_template("edit_profile.html", user=user, admin_allowed=is_admin_allowed())


@app.route("/profile/upload_avatar", methods=["POST"])
def upload_avatar():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    file = request.files.get("avatar")
    if file and file.filename:
        if not allowed_image(file.filename):
            return "Formato de imagen no permitido.", 400
        filename = secure_filename(f"user{user['id']}_{file.filename}")
        path = os.path.join(AVATAR_FOLDER, filename)
        file.save(path)
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET profile_image = ? WHERE id = ?",
            (filename, user["id"])
        )
        conn.commit()
    return redirect(url_for("profile", username=user["username"]))

# ================== GUARDADOS ==================


@app.route("/posts/<int:post_id>/save", methods=["POST"])
def toggle_save_post(post_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM saved_posts WHERE user_id = ? AND post_id = ?",
        (user["id"], post_id)
    )
    exists = cur.fetchone() is not None

    if exists:
        cur.execute("DELETE FROM saved_posts WHERE user_id = ? AND post_id = ?", (user["id"], post_id))
    else:
        cur.execute(
            "INSERT OR IGNORE INTO saved_posts (user_id, post_id) VALUES (?, ?)",
            (user["id"], post_id)
        )
    conn.commit()

    return redirect(request.referrer or url_for("index"))

# ================== BUSCADOR ==================


@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    username_filter = request.args.get("username", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    cur = conn.cursor()
    posts = []

    # Si q es @usuario y no hay más filtros, redirigimos al perfil
    if q.startswith("@") and not username_filter and not date_from and not date_to:
        username = q[1:]
        cur.execute("SELECT username FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row:
            return redirect(url_for("profile", username=row["username"]))

    # Si solo viene username_filter exacto, mandamos al perfil
    if username_filter and not q and not date_from and not date_to:
        cur.execute("SELECT username FROM users WHERE username = ?", (username_filter,))
        row = cur.fetchone()
        if row:
            return redirect(url_for("profile", username=row["username"]))

    where_clauses = []
    params = []

    if q:
        if q.startswith("#"):
            tag = q[1:].lower()
            where_clauses.append("t.tag = ?")
            params.append(tag)
        else:
            like_pattern = f"%{q}%"
            where_clauses.append(
                "(p.title LIKE ? OR p.content LIKE ? OR u.username LIKE ? OR c.content LIKE ?)"
            )
            params.extend([like_pattern, like_pattern, like_pattern, like_pattern])

    if username_filter:
        where_clauses.append("u.username LIKE ?")
        params.append(f"%{username_filter}%")

    if date_from:
        where_clauses.append("DATE(p.created_at) >= ?")
        params.append(date_from)

    if date_to:
        where_clauses.append("DATE(p.created_at) <= ?")
        params.append(date_to)

    sql = """
        SELECT DISTINCT p.id, p.title, p.content, p.image_filename, p.created_at,
               u.username, u.profile_image AS user_profile_image
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN comments c ON c.post_id = p.id
        LEFT JOIN post_tags t ON t.post_id = p.id
    """
    if where_clauses:
        sql += " WHERE " + " AND ".join(where_clauses)
    sql += " ORDER BY p.created_at DESC"

    if where_clauses:
        cur.execute(sql, tuple(params))
        posts = [dict(row) for row in cur.fetchall()]
    else:
        posts = []

    for p in posts:
        cur.execute(
            "SELECT reaction_type, COUNT(*) AS c FROM reactions WHERE post_id = ? GROUP BY reaction_type",
            (p["id"],)
        )
        p["reactions_by_type"] = {r["reaction_type"]: r["c"] for r in cur.fetchall()}

        cur.execute("SELECT COUNT(*) FROM comments WHERE post_id = ?", (p["id"],))
        p["comments_count"] = cur.fetchone()[0]

    user = current_user()
    return render_template(
        "search.html",
        q=q,
        username_filter=username_filter,
        date_from=date_from,
        date_to=date_to,
        posts=posts,
        user=user,
        admin_allowed=is_admin_allowed(),
        restricted=is_restricted(user)
    )


@app.route("/tag/<tag>")
def posts_by_tag(tag):
    cur = conn.cursor()
    cur.execute("""
        SELECT p.id, p.title, p.content, p.image_filename, p.created_at,
               u.username, u.profile_image AS user_profile_image
        FROM post_tags t
        JOIN posts p ON t.post_id = p.id
        JOIN users u ON p.user_id = u.id
        WHERE t.tag = ?
        ORDER BY p.created_at DESC
    """, (tag.lower(),))
    posts = [dict(row) for row in cur.fetchall()]

    user = current_user()
    return render_template(
        "search.html",
        q="#" + tag,
        username_filter="",
        date_from="",
        date_to="",
        posts=posts,
        user=user,
        admin_allowed=is_admin_allowed(),
        restricted=is_restricted(user)
    )

# ================== REPORTES / ADMIN / NOTIFICACIONES / SYNC ==================


@app.route("/reports/post/<int:post_id>", methods=["POST"])
def report_post(post_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    reason = request.form.get("reason", "").strip() or "Sin motivo"
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO reports (reporter_user_id, post_id, comment_id, reason) VALUES (?, ?, NULL, ?)",
        (user["id"], post_id, reason)
    )
    conn.commit()
    return redirect(request.referrer or url_for("index"))


@app.route("/reports/comment/<int:comment_id>", methods=["POST"])
def report_comment(comment_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    reason = request.form.get("reason", "").strip() or "Sin motivo"
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO reports (reporter_user_id, post_id, comment_id, reason) VALUES (?, NULL, ?, ?)",
        (user["id"], comment_id, reason)
    )
    conn.commit()
    return redirect(request.referrer or url_for("index"))


@app.route("/admin/dashboard")
def admin_dashboard():
    if not is_admin_allowed():
        return "No autorizado", 403

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    users_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM posts")
    posts_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM comments")
    comments_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM reports")
    reports_count = cur.fetchone()[0]

    cur.execute("""
        SELECT r.id, r.reason, r.created_at, u.username AS reporter,
               r.post_id, r.comment_id
        FROM reports r
        LEFT JOIN users u ON r.reporter_user_id = u.id
        ORDER BY r.created_at DESC
        LIMIT 20
    """)
    reports = [dict(row) for row in cur.fetchall()]

    return render_template(
        "admin_dashboard.html",
        users_count=users_count,
        posts_count=posts_count,
        comments_count=comments_count,
        reports_count=reports_count,
        reports=reports,
        user=current_user(),
        admin_allowed=True
    )


@app.route("/api/notifications/new")
def notifications_new_api():
    """Devuelve notificaciones nuevas para toasts y las marca como leídas."""
    user = current_user()
    if not user:
        return jsonify([])

    cur = conn.cursor()
    cur.execute("""
        SELECT id, type, data, created_at
        FROM notifications
        WHERE user_id = ? AND read = 0
        ORDER BY created_at DESC
        LIMIT 5
    """, (user["id"],))
    rows = cur.fetchall()

    items = []
    for r in rows:
        try:
            data = json.loads(r["data"] or "{}")
        except Exception:
            data = {}
        items.append({
            "id": r["id"],
            "type": r["type"],
            "data": data,
            "created_at": r["created_at"]
        })

    # marcamos como leídas las que acabamos de mandar
    cur.execute("UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0", (user["id"],))
    conn.commit()

    return jsonify(items)


@app.route("/admin/users/<int:user_id>/restrict", methods=["POST"])
def restrict_user(user_id):
    if not is_admin_allowed():
        return "No autorizado", 403

    minutes_str = request.form.get("minutes", "0").strip()
    try:
        minutes = int(minutes_str)
    except ValueError:
        minutes = 0

    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return "Usuario no encontrado", 404
    username = row["username"]

    if minutes <= 0:
        cur.execute("UPDATE users SET restricted_until = NULL WHERE id = ?", (user_id,))
    else:
        until = datetime.utcnow() + timedelta(minutes=minutes)
        cur.execute("UPDATE users SET restricted_until = ? WHERE id = ?", (until.isoformat(), user_id))
    conn.commit()

    return redirect(url_for("profile", username=username))


@app.route("/sync")
def sync_events():
    last_id = int(request.args.get("last_event_id", 0))
    cur = conn.cursor()
    cur.execute(
        "SELECT id, event_type, payload FROM events_log WHERE id > ? ORDER BY id ASC",
        (last_id,)
    )
    rows = cur.fetchall()
    events = []
    for r in rows:
        events.append({
            "id": r["id"],
            "event_type": r["event_type"],
            "payload": json.loads(r["payload"]),
        })
    return jsonify(events)


@app.route("/api/reactions_summary")
def reactions_summary():
    cur = conn.cursor()
    cur.execute("SELECT id FROM posts")
    post_ids = [row["id"] for row in cur.fetchall()]

    result = []
    for pid in post_ids:
        cur.execute(
            "SELECT reaction_type, COUNT(*) AS c FROM reactions WHERE post_id = ? GROUP BY reaction_type",
            (pid,)
        )
        reactions = {r["reaction_type"]: r["c"] for r in cur.fetchall()}
        cur.execute("SELECT COUNT(*) FROM comments WHERE post_id = ?", (pid,))
        comments_count = cur.fetchone()[0]
        result.append({
            "post_id": pid,
            "reactions": reactions,
            "comments_count": comments_count
        })
    return jsonify(result)


@app.route("/notifications")
def notifications_view():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    cur = conn.cursor()
    cur.execute("""
        SELECT *
        FROM notifications
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user["id"],))
    notifications = [dict(row) for row in cur.fetchall()]

    return render_template("notifications.html", notifications=notifications, user=user)


# ================== MAIN ==================

# ================== MAIN ==================

if __name__ == "__main__":
    # Para desarrollo local (Render usará gunicorn, no esto)
    app.run(host="0.0.0.0", port=5000)
