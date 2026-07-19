"""
安全中间件模块 - 鉴权、限流、爬虫拦截、安全响应头

课堂知识点对应：
- Flask框架安全缺陷 → login_required装饰器、CSRF、Session加固
- Burp Suite抓包篡改 → CSRF Token、Cookie安全、限流、统一错误
- FOFA网络空间测绘 → 指纹隐藏、爬虫拦截、IP白名单
"""
import re
import time
from functools import wraps
from flask import request, session, jsonify, abort, g, redirect, url_for

# ============================================================
# 1. 登录鉴权装饰器（抵御Flask未授权访问漏洞）
# ============================================================
def login_required(f):
    """
    要求用户已登录的装饰器。
    适用于 /message、/admin、/config 等需要鉴权的路由。

    攻击链路：FOFA扫描路由 → Burp直接访问未鉴权接口 → 数据泄露
    修复原理：所有敏感路由统一校验 session 中的登录状态
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            # 如果是API请求返回JSON，否则重定向到登录页
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "未授权，请先登录"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================
# 2. 管理员权限装饰器
# ============================================================
def admin_required(f):
    """
    仅允许admin角色访问的装饰器。
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "admin":
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "权限不足，需要管理员角色"}), 403
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


# ============================================================
# 3. 登录防爆破 - IP级别锁定
# ============================================================
# 内存中记录登录失败IP和次数
# 课堂：抵御Burp Suite Intruder字典爆破攻击
_LOGIN_ATTEMPTS = {}  # {ip: {"count": N, "lockout_until": timestamp}}


def check_login_lockout():
    """检查当前IP是否被锁定"""
    ip = request.remote_addr or "unknown"
    now = time.time()
    record = _LOGIN_ATTEMPTS.get(ip)
    if record:
        if record["lockout_until"] and now < record["lockout_until"]:
            remaining = int(record["lockout_until"] - now)
            return True, remaining
        if record["lockout_until"] and now >= record["lockout_until"]:
            # 锁定时间已过，重置
            del _LOGIN_ATTEMPTS[ip]
    return False, 0


def record_login_failure(max_attempts=5, lockout_minutes=10):
    """记录登录失败，超过阈值则锁定IP"""
    ip = request.remote_addr or "unknown"
    now = time.time()
    record = _LOGIN_ATTEMPTS.get(ip, {"count": 0, "lockout_until": 0})
    record["count"] += 1
    if record["count"] >= max_attempts:
        record["lockout_until"] = now + (lockout_minutes * 60)
    _LOGIN_ATTEMPTS[ip] = record


def reset_login_attempts():
    """登录成功后重置失败计数"""
    ip = request.remote_addr or "unknown"
    _LOGIN_ATTEMPTS.pop(ip, None)


# ============================================================
# 4. 爬虫拦截中间件（防御FOFA自动化探测）
# ============================================================
# 高频访问IP自动拉黑
_CRAWLER_BLACKLIST = set()  # 已被拉黑的IP
_CRAWLER_VISIT_LOG = {}     # {ip: [timestamp, ...]}
CRAWLER_MAX_REQUESTS = 60   # 60秒内允许的最大请求数
CRAWLER_WINDOW = 60         # 时间窗口（秒）
CRAWLER_BAN_SECONDS = 300   # 拉黑时长（秒）
_CRAWLER_BAN_EXPIRY = {}    # {ip: expiry_timestamp}


class CrawlerBlocker:
    """
    FOFA/爬虫拦截器 - 位于 Flask WSGI 中间件层

    攻击链路：FOFA自动化爬虫批量请求 → 扫描路由和指纹 → 资产暴露
    修复原理：高频IP自动拉黑，阻断自动化探测
    """

    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        app.wsgi_app = self

    def __call__(self, environ, start_response):
        ip = environ.get("REMOTE_ADDR", "unknown")
        now = time.time()

        # 检查是否已被拉黑
        if ip in _CRAWLER_BLACKLIST:
            if now < _CRAWLER_BAN_EXPIRY.get(ip, 0):
                # 仍在拉黑期：返回 429 Too Many Requests
                _response = b"Too Many Requests"
                status = "429 Too Many Requests"
                headers = [
                    ("Content-Type", "text/plain"),
                    ("Content-Length", str(len(_response))),
                    ("Retry-After", str(int(_CRAWLER_BAN_EXPIRY[ip] - now))),
                ]
                start_response(status, headers)
                return [_response]
            else:
                # 拉黑期已过，解封
                _CRAWLER_BLACKLIST.discard(ip)
                _CRAWLER_BAN_EXPIRY.pop(ip, None)

        # 记录访问
        if ip not in _CRAWLER_VISIT_LOG:
            _CRAWLER_VISIT_LOG[ip] = []
        visits = _CRAWLER_VISIT_LOG[ip]
        visits.append(now)

        # 清理超时记录
        _CRAWLER_VISIT_LOG[ip] = [t for t in visits if now - t < CRAWLER_WINDOW]

        # 检查是否超过阈值
        if len(_CRAWLER_VISIT_LOG[ip]) > CRAWLER_MAX_REQUESTS:
            _CRAWLER_BLACKLIST.add(ip)
            _CRAWLER_BAN_EXPIRY[ip] = now + CRAWLER_BAN_SECONDS
            _CRAWLER_VISIT_LOG.pop(ip, None)

        return self.app(environ, start_response)


# ============================================================
# 5. 安全响应头中间件（防御指纹识别 + XSS + 点击劫持）
# ============================================================
class SecurityHeadersMiddleware:
    """
    添加安全响应头，隐藏Flask框架指纹

    课堂知识点：
    - FOFA：删除X-Powered-By/修改Server，混淆框架特征
    - Burp：X-Frame-Options/XSS-Protection防御抓包后XSS
    """

    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        app.wsgi_app = self

    def __call__(self, environ, start_response):
        def _start_response(status, headers, exc_info=None):
            # 覆写Server头，不暴露框架类型/版本
            headers = [
                (k, v) for k, v in headers
                if k.lower() not in ("server", "x-powered-by")
            ]
            headers.append(("Server", "Web Server"))

            # 安全响应头
            security_headers = {
                "X-Frame-Options": "DENY",                    # 防御点击劫持
                "X-Content-Type-Options": "nosniff",          # 禁止MIME嗅探
                "X-XSS-Protection": "1; mode=block",           # 启用XSS过滤器
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            }
            for key, val in security_headers.items():
                # 避免重复添加
                if not any(k.lower() == key.lower() for k, _ in headers):
                    headers.append((key, val))

            return start_response(status, headers, exc_info)

        return self.app(environ, _start_response)


# ============================================================
# 6. 请求输入过滤（防御SQL注入和XSS）
# ============================================================
_SQL_PATTERNS = re.compile(
    r"(\bSELECT\b.*\bFROM\b|\bUNION\b.*\bSELECT\b|"
    r"\bDROP\b.*\bTABLE\b|\bDELETE\b.*\bFROM\b|"
    r"\bINSERT\b.*\bINTO\b|\bUPDATE\b.*\bSET\b|"
    r"--|\bOR\b\s+\d+\s*=\s*\d+|' OR '1'='1)",
    re.IGNORECASE
)

_XSS_PATTERNS = re.compile(
    r"<script[^>]*>.*?</script>|<[^>]*on\w+\s*=|javascript\s*:|"
    r"<iframe[^>]*>|<embed[^>]*>|<object[^>]*>",
    re.IGNORECASE
)


def sanitize_input(value):
    """
    过滤输入中的SQL注入和XSS恶意载荷

    攻击链路：Burp抓包篡改表单 → 注入SQL/XSS → 数据泄露/会话劫持
    修复原理：正则匹配常见攻击向量，提前阻断
    """
    if not isinstance(value, str):
        return value

    if _SQL_PATTERNS.search(value) or _XSS_PATTERNS.search(value):
        return None  # 恶意输入，返回None表示拒绝

    return value


def sanitize_form_data(form_data):
    """批量过滤表单数据"""
    sanitized = {}
    for key, val in form_data.items():
        if isinstance(val, str):
            cleaned = sanitize_input(val)
            if cleaned is None:
                return None  # 检测到恶意输入，拒绝整个请求
            sanitized[key] = cleaned
        else:
            sanitized[key] = val
    return sanitized


# ============================================================
# 7. Cookie加固设置函数
# ============================================================
def configure_session_cookie(app):
    """
    Cookie安全加固

    课堂知识点（Burp Suite防御）：
    - HttpOnly：抓包获取的Cookie无法被JS读取
    - Secure：仅HTTPS传输Cookie
    - SameSite=Lax：阻止CSRF跨站请求携带Cookie
    - Session过期：缩短会话有效期
    """
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,      # JS无法读取Cookie
        SESSION_COOKIE_SAMESITE="Lax",     # 跨站请求不发送Cookie
        SESSION_COOKIE_SECURE=False,       # 生产环境应设为True（HTTPS）
        SESSION_COOKIE_NAME="session_id",  # 默认名 Flask 太显眼
        PERMANENT_SESSION_LIFETIME=1800,   # 30分钟过期（秒）
    )
