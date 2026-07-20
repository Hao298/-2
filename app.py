# ==============================================================================
# Flask 用户管理系统
# 【增强 WAF】全局输入清洗 + 长度截断 + 类型校验 + 数据脱敏
# ==============================================================================

from flask import Flask, render_template, request, redirect, session, make_response
import sqlite3
import os
import io
import random
import re
import signal
from PIL import Image, ImageDraw, ImageFont

app = Flask(__name__)
app.secret_key = "dev-key-2025"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# 用户常量
# ---------------------------------------------------------------------------
USERS = {
    "admin": {
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "password": "alice2025",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}

# ===========================================================================
# 全局输入清洗层 — 请求前置过滤
# 覆盖：长度截断 / 空白符混淆 / 注释符混淆 / 7步手工注入探测阻断
# ===========================================================================

INPUT_MAX_LEN = 100        # 单个字段最大长度
KEYWORD_MAX_LEN = 50       # 搜索关键词最大长度
SQL_TIMEOUT = 2            # 单条 SQL 执行超时（秒），防御 SLEEP 延时盲注

# SQL 敏感关键字 — 阻断课堂 7 步手工注入探测
SQL_KEYWORDS = [
    "union", "select", "or", "and",            # 基本注入
    "order by", "group by",                     # 列数探测
    "group_concat", "concat", "concat_ws",      # 数据拼接
    "into", "from", "where",                     # 查询骨架
    "information_schema", "sys.schema",          # 元数据表
    "char", "chr", "ascii", "hex", "unhex",      # 编码函数
    "substr", "substring", "mid", "left",        # 截取函数
    "length", "if", "case when",                 # 条件判断
    "sleep", "benchmark", "delay",               # 时间盲注
    "load_file", "into outfile",                 # 文件操作
    "@@", "@@version", "version(", "database(",   # 系统变量、库名函数
    "exec", "xp_cmdshell",                       # 沙箱/系统命令
]

# 空白符混淆特征 — 用于拼接绕过检测
WHITESPACE_CHARS = {
    "\t", "\n", "\r", "\x0b", "\x0c",        # tab / 换行 / 回车 / 垂直制表 / 换页
    "\xa0",                                    # 不换行空格
    " ",                                       # 普通空格（多个连续也标记）
}

# 注释 / 特殊符号混淆
COMMENT_PATTERNS = [
    "/**/", "/*!", "--", "#", ";",             # SQL 注释 + 堆叠查询
    "/*", "*/", "/*+",                          # 不完整注释 / Oracle Hint
    "\\",                                       # 反斜杠转义
    "``",                                       # 反引号
]


def input_clean(value, field_type="string", max_len=INPUT_MAX_LEN):
    """统一输入清洗流水线：长度截断 → 注入特征检测 → 类型校验"""
    if not value:
        return value

    # ----- 1. 长度截断（抵御 AI 长段 Fuzz） -----
    if len(value) > max_len * 4:               # 远超阈值直接拒绝
        raise ValueError("WAF 拦截：输入超长（超过 400 字符）")
    value = value[:max_len]                    # 安全截断

    # ----- 2. URL 解码后的小写副本用于检测 -----
    raw = value
    decoded = _url_decode(value).lower()
    check_text = decoded

    # ----- 3. 空白符清洗 & 混淆检测 -----
    _detect_whitespace_obfuscation(check_text)

    # ----- 4. 注释符检测 -----
    for pat in COMMENT_PATTERNS:
        if pat in check_text:
            raise ValueError(f"WAF 拦截：检测到注释/特殊符号 {repr(pat)}")

    # ----- 5. 敏感关键字检测（全词匹配） -----
    for kw in SQL_KEYWORDS:
        # 用正则做全词匹配，防止 `username` 误杀 `name` 中的 `or`
        if re.search(r'\b' + re.escape(kw) + r'\b', check_text):
            raise ValueError(f"WAF 拦截：检测到敏感关键字 {kw}")

    # ----- 6. 单引号 / 双引号 / 反引号检测（字符串型注入闭合） -----
    for q in ["'", '"', "`"]:
        if q in check_text:
            raise ValueError(f"WAF 拦截：检测到非法引号 {repr(q)}")

    # ----- 7. 按字段类型做专项校验 -----
    if field_type == "digit":
        if not re.match(r'^\d+$', value):
            raise ValueError("WAF 拦截：数字字段包含非数字字符")
    elif field_type == "integer":
        # 严格整数校验：拒绝 + - * / . 等算术运算符，防止 id=3-1 探测
        if not re.match(r'^\d+$', value):
            raise ValueError("WAF 拦截：数字参数包含非法字符（拒绝算术表达式）")
    elif field_type == "phone":
        if not re.match(r'^\d{11}$', value):
            raise ValueError("手机号格式错误：必须为 11 位数字")
    elif field_type == "keyword":
        # 关键词：字母 / 数字 / @ / . / _ / -  + 中文
        if not re.match(r'^[\w@.\-一-鿿]+$', value):
            raise ValueError("WAF 拦截：搜索关键词包含非法字符")

    return value


def _url_decode(s):
    """双层 URL 解码 — 防御双重编码变形绕过（如 %2532 -> %32 -> 2）"""
    try:
        import urllib.parse
        decoded = s
        for _ in range(2):                     # 两次解码拦截双重编码
            prev = decoded
            decoded = urllib.parse.unquote(decoded)
            if decoded == prev:                # 无变化提前退出
                break
        return decoded
    except Exception:
        return s


def _detect_whitespace_obfuscation(text):
    """检测空白符混淆 —— 多个连续空格或非常见空白符 = 注入绕过尝试"""
    # 检查非常见空白符
    for ch in text:
        if ch in WHITESPACE_CHARS and ch != " ":
            raise ValueError(f"WAF 拦截：检测到非法空白符 {repr(ch)}")

    # 检查多个连续空格（SQL 注入常通过双空格绕过关键字检测）
    if "  " in text:    # 两个及以上连续空格
        raise ValueError("WAF 拦截：检测到连续空白符（可疑注入混淆）")


# ===========================================================================
# SQL 超时执行器 — 防御 SLEEP 延时盲注
# 底层阻断：所有数据库查询统一 2 秒超时
# ===========================================================================

class SQLTimeoutError(Exception):
    """自定义 SQL 超时异常"""
    pass


def _timeout_handler(signum, frame):
    """SIGALRM 信号处理 — 超时即抛出异常"""
    raise SQLTimeoutError("SQL 执行超时（检测到疑似 SLEEP 延时注入）")


def query_with_timeout(cursor, sql, params=None, timeout=SQL_TIMEOUT):
    """带超时保护的 SQL 执行包装器"""
    if params is None:
        params = ()
    # 设置信号超时
    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(timeout)
    try:
        result = cursor.execute(sql, params)
        signal.alarm(0)                         # 执行成功取消闹钟
        return result
    except SQLTimeoutError as e:
        signal.alarm(0)
        raise
    except Exception:
        signal.alarm(0)
        raise


# ===========================================================================
# 数据脱敏函数 — 搜索输出脱敏
# ===========================================================================

def mask_phone(phone):
    """手机号脱敏：13800138000 → 138****8000"""
    if not phone or len(phone) != 11:
        return phone
    return phone[:3] + "****" + phone[-4:]


def mask_email(email):
    """邮箱脱敏：admin@example.com → a***@example.com"""
    if not email or "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if len(local) <= 1:
        masked_local = local + "***"
    else:
        masked_local = local[0] + "***"
    return f"{masked_local}@{domain}"


def mask_username(username):
    """用户名脱敏：admin → a***"""
    if not username:
        return username
    if len(username) <= 1:
        return username + "***"
    return username[0] + "***"


# ===== 数据库初始化 =====

def init_db():
    db_dir = os.path.join(BASE_DIR, "data")
    os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(os.path.join(db_dir, "users.db"))
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT
    )""")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()
    print("[DB] 数据库初始化完成")


init_db()


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]
    return render_template("index.html", username=username, user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        captcha_input = request.form.get("captcha", "")

        if session.get("captcha") != captcha_input:
            return render_template("login.html", error="验证码错误")

        if username in USERS and USERS[username]["password"] == password:
            session["username"] = username
            user_info = USERS[username]
            return render_template("index.html", username=username, user=user_info)
        else:
            return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ===== 图形验证码 =====

@app.route("/captcha")
def captcha():
    code = str(random.randint(1000, 9999))
    session["captcha"] = code

    img = Image.new("RGB", (120, 40), (255, 255, 255))
    draw = ImageDraw.Draw(img)

    for _ in range(3):
        x1 = random.randint(0, 60)
        y1 = random.randint(0, 40)
        x2 = random.randint(60, 120)
        y2 = random.randint(0, 40)
        draw.line((x1, y1, x2, y2), fill=(random.randint(100, 200), random.randint(100, 200), random.randint(100, 200)), width=2)

    for _ in range(50):
        x = random.randint(0, 120)
        y = random.randint(0, 40)
        draw.point((x, y), fill=(random.randint(100, 200), random.randint(100, 200), random.randint(100, 200)))

    for i, ch in enumerate(code):
        x = 15 + i * 25
        y = random.randint(5, 15)
        r = random.randint(0, 120)
        g = random.randint(0, 120)
        b = random.randint(0, 120)
        draw.text((x, y), ch, fill=(r, g, b))

    buf = io.BytesIO()
    img.save(buf, "PNG")
    buf.seek(0)

    resp = make_response(buf.read())
    resp.content_type = "image/png"
    return resp


# ===== 用户注册 =====

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]
        phone = request.form["phone"]
        captcha_input = request.form.get("captcha", "")

        if session.get("captcha") != captcha_input:
            return render_template("register.html", username=session.get("username"), error="验证码错误")

        if email and "@" not in email:
            return render_template("register.html", username=session.get("username"), error="邮箱格式错误：必须包含 @ 符号")

        # WAF 输入清洗
        try:
            input_clean(username, "string")
            input_clean(password, "string")
            if email:
                input_clean(email, "string")
            input_clean(phone, "phone")
        except ValueError as e:
            return render_template("register.html", username=session.get("username"), error=str(e))

        conn = sqlite3.connect(os.path.join(BASE_DIR, "data", "users.db"))
        c = conn.cursor()
        try:
            query_with_timeout(c,
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, password, email, phone)
            )
            conn.commit()
            conn.close()
            return redirect("/login?msg=注册成功，请登录")
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", username=session.get("username"), error="注册失败：用户名已存在")
        except sqlite3.OperationalError as e:
            conn.close()
            return render_template("register.html", username=session.get("username"), error=f"注册失败：数据库异常 - {e}")

    return render_template("register.html", username=session.get("username"))


# ===== 用户搜索（需登录）=====

@app.route("/search")
def search():
    username = session.get("username")
    if not username or username not in USERS:
        return redirect("/login")

    keyword = request.args.get("keyword", "")
    results = []
    user_info = USERS[username]

    if keyword:
        try:
            input_clean(keyword, "keyword", KEYWORD_MAX_LEN)
        except ValueError as e:
            return render_template("index.html", username=username, user=user_info,
                                   search_results=[], keyword=keyword,
                                   search_error=str(e))

        conn = sqlite3.connect(os.path.join(BASE_DIR, "data", "users.db"))
        c = conn.cursor()
        try:
            like_pattern = f"%{keyword}%"
            rows = query_with_timeout(c,
                "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
                (like_pattern, like_pattern)
            ).fetchall()
            # 搜索结果脱敏：手机号 / 邮箱 / 用户名
            results = []
            for row in rows:
                results.append((
                    row[0],
                    mask_username(row[1]),
                    mask_email(row[2]),
                    mask_phone(row[3])
                ))
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            conn.close()
            return render_template("index.html", username=username, user=user_info,
                                   search_results=[], keyword=keyword,
                                   search_error=f"搜索异常：{e}")
        conn.close()

    return render_template(
        "index.html",
        username=username,
        user=user_info,
        search_results=results,
        keyword=keyword
    )


# ===== 找回密码 =====

@app.route("/forget_pwd", methods=["GET", "POST"])
def forget_pwd():
    if request.method == "POST":
        phone = request.form.get("phone", "")
        captcha_input = request.form.get("captcha", "")

        try:
            input_clean(phone, "phone")
        except ValueError as e:
            return render_template("forget_pwd.html", error=str(e))

        if session.get("captcha") != captcha_input:
            return render_template("forget_pwd.html", error="验证码错误")

        conn = sqlite3.connect(os.path.join(BASE_DIR, "data", "users.db"))
        c = conn.cursor()
        try:
            row = query_with_timeout(c, "SELECT username FROM users WHERE phone = ?", (phone,)).fetchone()
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
            conn.close()
            return render_template("forget_pwd.html", error=f"查询异常：{e}")
        conn.close()

        if row is None:
            return render_template("forget_pwd.html", error="该手机号未注册")

        session["reset_phone"] = phone
        return render_template("forget_pwd.html", step=2, phone=phone)

    return render_template("forget_pwd.html")


@app.route("/reset_pwd", methods=["POST"])
def reset_pwd():
    phone = session.get("reset_phone")
    if not phone:
        return redirect("/forget_pwd")

    new_pwd = request.form.get("new_password", "")
    confirm_pwd = request.form.get("confirm_password", "")

    if new_pwd != confirm_pwd:
        return render_template("forget_pwd.html", step=2, phone=phone, error="两次密码输入不一致")
    if not new_pwd:
        return render_template("forget_pwd.html", step=2, phone=phone, error="密码不能为空")

    try:
        input_clean(new_pwd, "string")
    except ValueError as e:
        return render_template("forget_pwd.html", step=2, phone=phone, error=str(e))

    conn = sqlite3.connect(os.path.join(BASE_DIR, "data", "users.db"))
    c = conn.cursor()
    try:
        query_with_timeout(c, "UPDATE users SET password = ? WHERE phone = ?", (new_pwd, phone))
        conn.commit()
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
        conn.close()
        return render_template("forget_pwd.html", step=2, phone=phone, error=f"重置失败：{e}")
    conn.close()

    session.pop("reset_phone", None)
    return redirect("/login?msg=密码重置成功，请登录")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
