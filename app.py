import json
import os
import sqlite3
import bcrypt
from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = "dev-key-2025"


# ===== 数据库初始化 =====

def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT
    )""")
    # 插入默认用户（INSERT OR IGNORE 防止重复）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('admin', 'admin123', 'admin@test.com', '13800138000')")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('alice', 'alice2025', 'alice@test.com', '13900139000')")
    conn.commit()
    conn.close()
    print("[DB] 数据库初始化完成")


# 启动时初始化数据库
init_db()


USERS_JSON = os.environ.get("USERS_JSON")
if not USERS_JSON:
    raise RuntimeError("环境变量 USERS_JSON 未设置")

_raw_users = json.loads(USERS_JSON)
USERS = {}
for username, info in _raw_users.items():
    hashed = bcrypt.hashpw(info["password"].encode("utf-8"), bcrypt.gensalt())
    user = {k: v for k, v in info.items() if k != "password"}
    user["password"] = hashed
    USERS[username] = user

del _raw_users


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = {k: v for k, v in USERS[username].items() if k != "password"}
    return render_template("index.html", username=username, user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username in USERS and bcrypt.checkpw(
            password.encode("utf-8"), USERS[username]["password"]
        ):
            session["username"] = username
            user_info = {k: v for k, v in USERS[username].items() if k != "password"}
            return render_template("index.html", username=username, user=user_info)
        else:
            return render_template("login.html", username=session.get("username"), error="用户名或密码错误")
    return render_template("login.html", username=session.get("username"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ===== 用户注册 =====

@app.route("/register", methods=["GET", "POST"])
def register():
    """用户注册 - 使用 f-string 字符串拼接构造 SQL（教学演示用）"""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]
        phone = request.form["phone"]

        # 使用 f-string 字符串拼接插入数据库（故意不安全，仅用于教学演示）
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print(f"[SQL] {sql}")
        c.execute(sql)
        conn.commit()
        conn.close()

        return redirect("/login?msg=注册成功，请登录")

    return render_template("register.html", username=session.get("username"))


# ===== 用户搜索 =====

@app.route("/search")
def search():
    """用户搜索 - 使用 f-string 字符串拼接构造 SQL（教学演示用）"""
    keyword = request.args.get("keyword", "")
    results = []

    if keyword:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        # 使用 f-string 字符串拼接查询（故意不安全，仅用于教学演示）
        sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[SQL] {sql}")
        results = c.execute(sql).fetchall()
        conn.close()

    return render_template(
        "index.html",
        username=session.get("username"),
        search_results=results,
        keyword=keyword
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
