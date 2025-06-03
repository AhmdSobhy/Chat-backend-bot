import os
from flask import Flask, request, jsonify, Response
import openai
import sqlite3
from datetime import datetime, timedelta
import jwt
from functools import wraps
import tiktoken
from dotenv import load_dotenv
import secrets

# تحميل متغيرات البيئة
load_dotenv()
app = Flask(__name__)
openai.api_key = os.getenv("OPENAI_API_KEY")
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "mysecret")

# محتوى البورتفوليو
portfolio_text = """
(اكتب هنا محتوى البورتفوليو المستخرج من PDF)
"""

# إنشاء قاعدة البيانات
def init_db():
    conn = sqlite3.connect("chat_app.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS projects (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, name TEXT, description TEXT, created_at TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, message TEXT, reply TEXT, tokens INTEGER, timestamp TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS refresh_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, token TEXT, expires_at TEXT)")
    conn.commit()
    conn.close()

init_db()

# حماية بالتوكن
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace("Bearer ", "")
        if not token:
            return jsonify({"message": "Token is missing"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user_id']
        except:
            return jsonify({"message": "Token is invalid"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# تسجيل مستخدم
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    conn = sqlite3.connect("chat_app.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (data['username'], data['password'], 'user'))
        conn.commit()
        return jsonify({"message": "User registered successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409
    finally:
        conn.close()

# تسجيل دخول
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    conn = sqlite3.connect("chat_app.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (data['username'], data['password']))
    user = c.fetchone()
    if user:
        user_id = user[1]
        access_token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        refresh_token = secrets.token_hex(32)
        expires_at = (datetime.utcnow() + timedelta(days=30)).isoformat()
        c.execute("INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)", (user_id, refresh_token, expires_at))
        conn.commit()
        conn.close()
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token})
    conn.close()
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/refresh', methods=['POST'])
def refresh():
    data = request.json
    refresh_token = data.get('refresh_token')
    if not refresh_token:
        return jsonify({'error': 'Refresh token is required'}), 400
    conn = sqlite3.connect("chat_app.db")
    c = conn.cursor()
    c.execute("SELECT user_id, expires_at FROM refresh_tokens WHERE token=?", (refresh_token,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Invalid refresh token'}), 401
    user_id, expires_at = row
    if datetime.fromisoformat(expires_at) < datetime.utcnow():
        c.execute("DELETE FROM refresh_tokens WHERE token=?", (refresh_token,))
        conn.commit()
        conn.close()
        return jsonify({'error': 'Refresh token expired'}), 401
    # Optionally rotate refresh token
    new_refresh_token = secrets.token_hex(32)
    new_expires_at = (datetime.utcnow() + timedelta(days=30)).isoformat()
    c.execute("UPDATE refresh_tokens SET token=?, expires_at=? WHERE token=?", (new_refresh_token, new_expires_at, refresh_token))
    access_token = jwt.encode({
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    conn.commit()
    conn.close()
    return jsonify({'access_token': access_token, 'refresh_token': new_refresh_token})

# شات مع GPT (streaming)
@app.route('/chat', methods=['POST'])
@token_required
def chat(current_user):
    user_message = request.json['message']
    full_prompt = f"{portfolio_text}\n{user_message}"
    encoding = tiktoken.encoding_for_model("gpt-3.5-turbo")
    token_count = len(encoding.encode(full_prompt))

    messages = [
        {"role": "system", "content": "أنت مساعد ذكي تمثل الشركة. استخدم بيانات البورتفوليو للرد على الأسئلة."},
        {"role": "system", "content": f"Portfolio data: {portfolio_text}"},
        {"role": "user", "content": user_message}
    ]

    def generate():
        full_reply = ""
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=messages,
            stream=True
        )
        for chunk in response:
            content = chunk['choices'][0]['delta'].get('content', '')
            full_reply += content
            yield content

        conn = sqlite3.connect("chat_app.db")
        c = conn.cursor()
        c.execute("INSERT INTO messages (user_id, message, reply, tokens, timestamp) VALUES (?, ?, ?, ?, ?)",
                  (current_user, user_message, full_reply.strip(), token_count, str(datetime.now())))
        conn.commit()
        conn.close()

    return Response(generate(), content_type='text/plain')

# سجل المحادثات
@app.route('/history', methods=['GET'])
@token_required
def history(current_user):
    conn = sqlite3.connect("chat_app.db")
    c = conn.cursor()
    c.execute("SELECT message, reply, tokens, timestamp FROM messages WHERE user_id=? ORDER BY timestamp", (current_user,))
    rows = c.fetchall()
    conn.close()
    return jsonify({"history": [{"message": r[0], "reply": r[1], "tokens": r[2], "timestamp": r[3]} for r in rows]})

# إدارة المشاريع
@app.route('/projects', methods=['GET'])
@token_required
def list_projects(current_user):
    conn = sqlite3.connect("chat_app.db")
    c = conn.cursor()
    c.execute("SELECT id, name, description, created_at FROM projects WHERE user_id=?", (current_user,))
    projects = [{"id": r[0], "name": r[1], "description": r[2], "created_at": r[3]} for r in c.fetchall()]
    conn.close()
    return jsonify({"projects": projects})

@app.route('/projects', methods=['POST'])
@token_required
def create_project(current_user):
    data = request.json
    conn = sqlite3.connect("chat_app.db")
    c = conn.cursor()
    c.execute("INSERT INTO projects (user_id, name, description, created_at) VALUES (?, ?, ?, ?)",
              (current_user, data['name'], data.get('description', ''), str(datetime.now())))
    conn.commit()
    conn.close()
    return jsonify({"message": "Project created"})

@app.route('/projects/<int:pid>', methods=['PUT'])
@token_required
def update_project(current_user, pid):
    data = request.json
    conn = sqlite3.connect("chat_app.db")
    c = conn.cursor()
    c.execute("UPDATE projects SET name=?, description=? WHERE id=? AND user_id=?",
              (data['name'], data.get('description', ''), pid, current_user))
    conn.commit()
    conn.close()
    return jsonify({"message": "Project updated"})

@app.route('/projects/<int:pid>', methods=['DELETE'])
@token_required
def delete_project(current_user, pid):
    conn = sqlite3.connect("chat_app.db")
    c = conn.cursor()
    c.execute("DELETE FROM projects WHERE id=? AND user_id=?", (pid, current_user))
    conn.commit()
    conn.close()
    return jsonify({"message": "Project deleted"})

# جلب جميع المستخدمين (للاستخدام الإداري فقط)
@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    conn = sqlite3.connect("chat_app.db")
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users")
    users = [{"id": r[0], "username": r[1], "role": r[2]} for r in c.fetchall()]
    conn.close()
    return jsonify({"users": users})

if __name__ == '__main__':
    app.run(debug=True)