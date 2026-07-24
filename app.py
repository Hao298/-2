# ==============================================================================
# Flask 用户管理系统
# 【增强 WAF】全局输入清洗 + 长度截断 + 类型校验 + 数据脱敏
# ==============================================================================

from flask import Flask, render_template, request, redirect, session, make_response, url_for, send_from_directory
import sqlite3
import os
import io
import random
import re
import signal
import uuid
import datetime
import logging
import secrets
from collections import defaultdict
from PIL import Image, ImageDraw, ImageFont

app = Flask(__name__)
app.secret_key = "dev-key-2025"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB 上传限制
# CSRF防护：Session同源策略 — 限制Cookie在跨站请求中发送
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


# ===== CSRF防护 — 生成会话Token（对应课堂CSRF Token加固方案） =====

@app.before_request
def generate_csrf_token():
    """每个请求前确保session中有CSRF Token"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)  # 32位随机十六进制Token

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
RECHARGE_MIN = 0.01        # 单次充值最低金额
RECHARGE_MAX = 100000      # 单次充值最高金额

# 文件包含防护 — pages目录与白名单
PAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
ALLOWED_PAGES = {"help", "about", "terms"}   # 第一层防护：合法页面白名单

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

class SQLTimeoutError(sqlite3.DatabaseError):
    """自定义 SQL 超时异常（继承 sqlite3.DatabaseError，确保被现有 except 捕获）"""
    pass


def _timeout_handler(signum, frame):
    """SIGALRM 信号处理 — 超时即抛出异常"""
    raise SQLTimeoutError("SQL 执行超时（检测到疑似 SLEEP 延时注入）")


def query_with_timeout(cursor, sql, params=None, timeout=SQL_TIMEOUT):
    """带超时保护的 SQL 执行包装器（signal.alarm 仅在主线程可用）"""
    if params is None:
        params = ()
    timeouted = False
    # 尝试设置信号超时（debug 模式子线程中不可用，静默跳过）
    try:
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(timeout)
    except (ValueError, AttributeError):
        pass  # 非主线程或 Windows 不支持 signal.alarm
    try:
        result = cursor.execute(sql, params)
        if not timeouted:
            try:
                signal.alarm(0)
            except (ValueError, AttributeError):
                pass
        return result
    except SQLTimeoutError as e:
        timeouted = True
        try:
            signal.alarm(0)
        except (ValueError, AttributeError):
            pass
        raise
    except Exception:
        try:
            signal.alarm(0)
        except (ValueError, AttributeError):
            pass
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


# ===========================================================================
# 上传模块 — 纵深防御配置
# ===========================================================================

# ① IP 限流：每 IP 每分钟最多上传 5 次
UPLOAD_RATE_LIMIT = 5          # 最大请求次数
UPLOAD_RATE_WINDOW = 60        # 时间窗口（秒）
_rate_store = defaultdict(list)  # {ip: [timestamp, ...]}


def check_rate_limit(ip, max_requests=5, window=60):
    """检查 IP 是否超出频率限制"""
    now = datetime.datetime.now().timestamp()
    window_start = now - window
    # 清理过期记录
    _rate_store[ip] = [t for t in _rate_store[ip] if t > window_start]
    if len(_rate_store[ip]) >= max_requests:
        return False
    _rate_store[ip].append(now)
    return True


# ② 上传日志器
UPLOAD_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "upload.log")
os.makedirs(os.path.dirname(UPLOAD_LOG_PATH), exist_ok=True)

upload_logger = logging.getLogger("upload_audit")
upload_logger.setLevel(logging.INFO)
_ul_handler = logging.FileHandler(UPLOAD_LOG_PATH, encoding="utf-8")
_ul_handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
upload_logger.addHandler(_ul_handler)


def log_upload(username, client_ip, original_name, stored_name):
    """记录上传日志：用户名、客户端 IP、原始文件名、存储文件名"""
    upload_logger.info(
        f"USER={username}  IP={client_ip}  ORIG={original_name}  SAVE={stored_name}"
    )


# ②-b 余额审计日志器
BALANCE_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "balance.log")
os.makedirs(os.path.dirname(BALANCE_LOG_PATH), exist_ok=True)

balance_logger = logging.getLogger("balance_audit")
balance_logger.setLevel(logging.INFO)
_bl_handler = logging.FileHandler(BALANCE_LOG_PATH, encoding="utf-8")
_bl_handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
balance_logger.addHandler(_bl_handler)


def log_balance_change(username, client_ip, amount, new_balance):
    """记录余额变动日志：用户名、IP、变更金额、操作后余额"""
    balance_logger.info(
        f"USER={username}  IP={client_ip}  AMOUNT={amount:+.2f}  BALANCE={new_balance:.2f}"
    )


# ③ 恶意特征过滤（文件内容级）
MALICIOUS_PATTERNS = [
    b"<?php", b"<?=", b"<?PHP",               # PHP 代码
    b"<script", b"javascript:",                 # XSS 脚本
    b"onerror=", b"onload=", b"onclick=",       # 事件处理器
    b"eval(", b"base64_decode(", b"system(",    # 危险函数
    b"exec(", b"passthru(", b"shell_exec(",     # 命令执行
    b"<?xml", b"<!ENTITY",                       # XXE
    b"#! /bin/sh", b"#! /bin/bash",             # Shell 脚本头
    b"<%@",                                      # ASP 标记
    b"Content-Type:",                            # 邮件头注入
]


def scan_malicious_content(data):
    """扫描二进制数据中的恶意特征"""
    data_lower = data.lower()
    for pattern in MALICIOUS_PATTERNS:
        if pattern in data or pattern.lower() in data_lower:
            raise ValueError(f"上传失败：文件内容包含恶意特征 {pattern[:20]}")
    return data


# ③-b IDOR 批量探测恶意特征过滤
IDOR_PROBE_PATTERNS = [
    "union select", "union all select",   # SQL注入批量探测
    "information_schema",                   # 元数据探测
    "sleep(", "benchmark(",                 # 时间盲注
    "1=1", "1=2", "1=0",                   # 布尔探测
    "admin'", "admin\"",                    # 管理员账户探测
    "/*", "*/", "--",                       # 注释符探测
]


def filter_idor_probe(value):
    """拦截 IDOR 批量探测特征"""
    if not value:
        return value
    val_lower = value.lower()
    for pattern in IDOR_PROBE_PATTERNS:
        if pattern in val_lower:
            raise ValueError("WAF 拦截：检测到 IDOR 批量探测特征")


# ④ 安全响应头 — 禁止浏览器执行 /static/uploads/ 目录下的脚本
@app.after_request
def set_upload_security_headers(response):
    """为 /static/uploads/ 路径添加安全响应头"""
    if request.path.startswith("/static/uploads/"):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Disposition"] = 'inline'
    return response


# ===== 用户头像上传（加固版） =====

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif"}   # 白名单后缀
ALLOWED_MIME_PREFIXES = {"image/"}                     # MIME 白名单前缀

# 图片魔数字典（文件头部二进制特征）
MAGIC_NUMBERS = {
    b"\xFF\xD8\xFF":           "jpg/jpeg",   # JPEG 头部
    b"\x89PNG\r\n\x1A\n":     "png",         # PNG 头部
    b"GIF87a":                 "gif",         # GIF87a 头部
    b"GIF89a":                 "gif",         # GIF89a 头部
}


def sanitize_filename(filename):
    """文件名清洗：过滤路径穿越与截断字符"""
    # 过滤 ../ ./
    filename = filename.replace("../", "").replace("./", "")
    # 过滤 / \ %00
    filename = filename.replace("/", "").replace("\\", "").replace("\x00", "")
    # 过滤末尾空格、连续点号（Windows 特性绕过）
    filename = filename.rstrip(" .")
    # 替换文件中间连续点号为单点（防御 shell..png 绕过）
    while ".." in filename:
        filename = filename.replace("..", ".")
    # 过滤 ::$DATA 等 Windows 备用数据流特征
    if "::$DATA" in filename.upper():
        filename = ""
    # 过滤 .htaccess
    if filename.lower() == ".htaccess" or filename.lower().startswith(".htaccess"):
        filename = ""
    return filename


def validate_magic(fileobj):
    """读取文件头部二进制魔数，校验图片真实类型"""
    # 保存当前文件指针位置
    pos = fileobj.tell()
    # 读取前 8 个字节
    header = fileobj.read(8)
    # 恢复文件指针
    fileobj.seek(pos)
    if not header:
        return False
    # 逐条比对魔数
    for magic, _ in MAGIC_NUMBERS.items():
        if header.startswith(magic):
            return True
    return False


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """用户头像上传 — 白名单后缀 + UUID 重命名 + MIME 校验 + 异常捕获"""
    username = session.get("username")
    if not username or username not in USERS:
        return redirect("/login")

    if request.method == "POST":
        try:
            file = request.files.get("file")
            if not file or file.filename == "":
                return render_template("upload.html", username=username, error="请选择要上传的文件")

            # ⏱ 限流检查：每 IP 每分钟最多上传 5 次
            client_ip = request.remote_addr or "0.0.0.0"
            if not check_rate_limit(client_ip):
                return render_template("upload.html", username=username, error="上传过于频繁，请稍后再试")

            original_name = file.filename

            # ① 文件名清洗（过滤 ../ / \ %00 + 末尾空格 + 连续点号 + .htaccess + ::$DATA）
            clean_name = sanitize_filename(original_name)
            if clean_name != original_name or clean_name == "":
                return render_template("upload.html", username=username, error="上传失败：文件名包含非法字符或路径穿越特征")

            # ② 提取后缀并转小写
            if "." not in clean_name:
                return render_template("upload.html", username=username, error="上传失败：文件缺少后缀名")
            ext = clean_name.rsplit(".", 1)[1].lower()

            # ③ 白名单校验
            if ext not in ALLOWED_EXTENSIONS:
                return render_template("upload.html", username=username, error=f"上传失败：不允许的文件类型 .{ext}，仅支持 jpg/jpeg/png/gif")

            # ④ 双后缀检测（如 shell.jpg.php）
            parts = clean_name.lower().split(".")
            if len(parts) > 2:
                # 检查中间部分是否也包含可执行后缀
                suspicious_exts = {"php", "php3", "php4", "php5", "phtml", "asp", "aspx",
                                   "jsp", "exe", "sh", "py", "pl", "cgi", "htaccess", "shtml"}
                for p in parts[:-1]:
                    if p in suspicious_exts or p in ALLOWED_EXTENSIONS:
                        # 中间部分是已知后缀 → 双后缀畸形文件
                        return render_template("upload.html", username=username,
                                               error=f"上传失败：禁止上传双后缀文件")

            # ⑤ 魔数校验（读取文件头部二进制特征）
            if not validate_magic(file):
                return render_template("upload.html", username=username,
                                       error="上传失败：文件头部魔数不匹配，非图片文件")

            # ⑤-b 恶意特征扫描（PHP/脚本/危险函数等）
            file_content = file.read()
            file.seek(0)
            try:
                scan_malicious_content(file_content)
            except ValueError as e:
                return render_template("upload.html", username=username, error=str(e))

            # ⑥ 校验 Content-Type（仅当明确设置且非空时拦截非图片类型）
            content_type = file.content_type or ""
            if content_type and not any(content_type.startswith(prefix) for prefix in ALLOWED_MIME_PREFIXES):
                return render_template("upload.html", username=username, error="上传失败：请求 Content-Type 非图片类型")

            # ⑦ UUID 重命名（放弃原始文件名）
            new_filename = f"{uuid.uuid4().hex}.{ext}"
            upload_dir = os.path.join(BASE_DIR, "static", "uploads")
            os.makedirs(upload_dir, exist_ok=True)

            filepath = os.path.join(upload_dir, new_filename)
            file.save(filepath)

            # ⑧ 记录上传日志
            log_upload(username, client_ip, original_name, new_filename)

            # ⑨ 生成访问 URL
            file_url = url_for("static", filename=f"uploads/{new_filename}")

            return render_template("upload.html", username=username, success=True,
                                   filename=new_filename, file_url=file_url)

        except Exception as e:
            return render_template("upload.html", username=username, error=f"上传失败：{e}")

    return render_template("upload.html", username=username)


# ===== 个人中心（加固版 — 仅查询当前登录用户） =====

@app.route("/profile")
def profile():
    """个人中心 - 仅查询当前登录用户自身信息"""
    try:
        # ① 身份只从 session 读取
        cur_username = session.get("username")
        if not cur_username or cur_username not in USERS:
            return redirect("/login")

        # ② 从 SQLite 查询当前登录用户 ID
        conn = sqlite3.connect(os.path.join(BASE_DIR, "data", "users.db"))
        c = conn.cursor()
        row = c.execute("SELECT id, username, email, phone FROM users WHERE username = ?", (cur_username,)).fetchone()
        conn.close()

        if row is None:
            return render_template("profile.html", username=cur_username, error="用户数据异常")

        user_data = {
            "id": row[0],
            "username": row[1],
            "email": mask_email(row[2]) if row[2] else "",
            "phone": mask_phone(row[3]) if row[3] else "",
        }
        # 从 USERS 字典补充角色和余额
        dict_user = USERS.get(row[1])
        if dict_user:
            user_data["role"] = dict_user.get("role", "user")
            user_data["balance"] = dict_user.get("balance", 0)
        else:
            user_data["role"] = "user"
            user_data["balance"] = 0

        return render_template("profile.html", username=cur_username, user=user_data,
                               csrf_token=session.get("csrf_token"))

    except Exception as e:
        return render_template("profile.html", username=session.get("username"), error=f"查询异常：{e}")


# ===== 充值（加固版 — session身份 + amount正数校验） =====

@app.route("/recharge", methods=["POST"])
def recharge():
    """充值 - 仅作用于当前登录用户，amount > 0 强制校验"""
    try:
        # ① 身份只从 session 读取
        cur_username = session.get("username")
        if not cur_username or cur_username not in USERS:
            return redirect("/login")

        # ①-b IP 限流：每 IP 每分钟最多充值 10 次
        client_ip = request.remote_addr or "0.0.0.0"
        if not check_rate_limit(client_ip, max_requests=10, window=60):
            return render_template("profile.html", username=cur_username, error="充值过于频繁，请稍后再试")

        # ①-c IDOR 探测特征过滤
        try:
            filter_idor_probe(cur_username)
        except ValueError as e:
            return render_template("profile.html", username=cur_username, error=str(e))

        # ② amount 严格校验：只允许纯数字 + 最多一个小数点
        amount_str = request.form.get("amount", "").strip()
        if not amount_str:
            return render_template("profile.html", username=cur_username, error="充值失败：金额不能为空")

        # 过滤换行、空格、特殊符号等畸形载荷
        if not re.match(r'^\d+(\.\d{1,2})?$', amount_str):
            return render_template("profile.html", username=cur_username, error="充值失败：金额必须为正整数或小数（最多两位）")

        amount = float(amount_str)
        if amount <= 0:
            return render_template("profile.html", username=cur_username, error="充值失败：金额必须大于 0")

        # 单次充值上下限
        if amount < RECHARGE_MIN:
            return render_template("profile.html", username=cur_username, error=f"充值失败：单次最低充值 {RECHARGE_MIN} 元")
        if amount > RECHARGE_MAX:
            return render_template("profile.html", username=cur_username, error=f"充值失败：单次最高充值 {RECHARGE_MAX} 元")

        # ③ 更新当前登录用户余额
        USERS[cur_username]["balance"] = USERS[cur_username]["balance"] + amount

        # ③-b 记录余额审计日志
        log_balance_change(cur_username, client_ip, amount, USERS[cur_username]["balance"])

        return redirect("/profile")

    except Exception as e:
        return render_template("profile.html", username=session.get("username"), error=f"充值异常：{e}")


# ===== 动态页面加载（三层防护 — 文件包含 + 路径遍历 防御） =====

@app.route("/page")
def dynamic_page():
    """动态页面加载 — 已按《文件包含漏洞原理与实战利用培训》实施三层防御"""
    name = request.args.get("name", "")
    page_content = ""

    if name:
        # =========================================================================
        # 第三层防护：过滤课件中全部危险特征字符串与伪协议
        # 覆盖：../ ./ \ file:// php:// data:// ftp:// expect://
        # 对应知识点：伪协议文件包含、目录遍历字符绕过
        # =========================================================================
        blocked_patterns = [
            "../", "..\\", "./", ".\\",        # 目录穿越
            "file://", "php://", "data://",     # PHP伪协议
            "ftp://", "expect://", "zip://",    # 其他伪协议
            "\\\\", "%00", "\x00",              # 截断攻击
        ]
        name_lower = name.lower()
        for pattern in blocked_patterns:
            if pattern in name_lower or pattern in name:
                page_content = "页面不存在"
                break

        if not page_content:
            # =========================================================================
            # 第一层防护：合法页面白名单
            # 仅允许白名单内的页面名称，拦截陌生参数
            # 对应知识点：文件包含的入口管控
            # =========================================================================
            page_name = name.split("/")[-1].split("\\")[-1]  # 提取纯文件名
            if page_name not in ALLOWED_PAGES:
                page_content = "页面不存在"

        if not page_content:
            # =========================================================================
            # 第二层防护：路径规范化锁定 pages 根目录
            # 将 name 拼接后转为绝对路径，校验是否以 PAGES_DIR 开头
            # 阻断 ../ 多级目录穿越逃逸
            # 对应知识点：路径遍历的根本性防御
            # =========================================================================
            safe_name = name.replace("../", "").replace("..\\", "")
            safe_name = safe_name.replace("/", "").replace("\\", "")
            safe_name = safe_name.replace("\x00", "")

            # 尝试 .html 后缀后读取
            page_path = os.path.join(PAGES_DIR, safe_name + ".html")
            real_path = os.path.normpath(page_path)

            # 路径前缀锁定：禁止访问 PAGES_DIR 以外的任何目录
            if not real_path.startswith(os.path.normpath(PAGES_DIR) + os.sep) and \
               real_path != os.path.normpath(PAGES_DIR):
                page_content = "页面不存在"
            elif os.path.exists(real_path):
                with open(real_path, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                page_content = "页面不存在"

    # 获取当前用户信息（原有逻辑不变）
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]

    return render_template("index.html", username=username, user=user_info, page_content=page_content)


# ===== 修改密码（加固版 — CSRF Token + Referer + 身份锁定 + 旧密码校验） =====

@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码 — 已按《XSS与CSRF攻防实战培训》CSRF防御标准加固"""
    # ① 登录校验（未登录不可修改）
    cur_username = session.get("username")
    if not cur_username:
        return redirect("/login")

    # 获取用户信息用于错误时回显表单
    dict_user = USERS.get(cur_username, {})
    user_data = {
        "id": 0, "username": cur_username,
        "email": dict_user.get("email", ""),
        "phone": dict_user.get("phone", ""),
        "role": dict_user.get("role", ""),
        "balance": dict_user.get("balance", 0),
    }
    sess_token = session.get("csrf_token", "")

    # =========================================================================
    # CSRF防御 ① — Token校验（对应课堂：CSRF Token缺失漏洞修复）
    # 后端强制校验表单提交的Token与session中Token是否一致
    # =========================================================================
    form_token = request.form.get("csrf_token", "")
    if not form_token or form_token != sess_token:
        return render_template("profile.html", username=cur_username, user=user_data,
                               error="CSRF攻击拦截：Token验证失败", csrf_token=sess_token)

    # =========================================================================
    # CSRF防御 ② — Referer来源校验（对应课堂：CSRF Referer防御）
    # 仅允许本站域名发起的改密请求，拦截外部钓鱼站点跨站请求
    # =========================================================================
    referer = request.headers.get("Referer", "")
    if referer:
        allowed_prefixes = [
            "http://192.168.126.133:5000", "http://127.0.0.1:5000",
            "http://localhost:5000",
        ]
        if not any(referer.startswith(p) for p in allowed_prefixes):
            return render_template("profile.html", username=cur_username, user=user_data,
                                   error="CSRF攻击拦截：非法来源请求", csrf_token=sess_token)

    # =========================================================================
    # 水平越权修复：不从表单接收username，从session读取（对应课堂：IDOR修复）
    # =========================================================================
    target_username = cur_username

    # =========================================================================
    # 原密码校验（对应课堂：业务安全拓展 — 敏感操作二次验证）
    # =========================================================================
    old_password = request.form.get("old_password", "")
    if USERS.get(target_username, {}).get("password") != old_password:
        return render_template("profile.html", username=cur_username, user=user_data,
                               error="原密码错误", csrf_token=sess_token)

    # 新密码校验
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    if not new_password:
        return render_template("profile.html", username=cur_username, user=user_data,
                               error="密码不能为空", csrf_token=sess_token)
    if new_password != confirm_password:
        return render_template("profile.html", username=cur_username, user=user_data,
                               error="两次密码输入不一致", csrf_token=sess_token)

    # 更新密码
    USERS[target_username]["password"] = new_password
    return redirect("/profile")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
