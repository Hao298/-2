import json
import os
import bcrypt
from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = "dev-key-2025"

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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
