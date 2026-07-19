"""
配置加载模块 - 从系统环境变量/%s 读取配置
绝不包含明文密钥，禁止硬编码任何凭证
"""
import os
from dotenv import load_dotenv

# 加载 .env 文件（仅开发环境；生产使用真实环境变量）
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))


def getenv_bool(key, default=False):
    """将环境变量字符串转为布尔值"""
    val = os.environ.get(key, str(default)).strip().lower()
    return val in ("true", "1", "yes", "on")


def getenv_int(key, default=0):
    """将环境变量转为整数"""
    try:
        return int(os.environ.get(key, default))
    except (ValueError, TypeError):
        return default


class AppConfig:
    """应用配置类 - 统一从环境变量加载"""

    # ---- Flask 基础 ----
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "")
    DEBUG = getenv_bool("FLASK_DEBUG", False)
    HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
    PORT = getenv_int("FLASK_PORT", 5000)

    # ---- 用户凭证（仅存储 bcrypt 哈希，无明文密码） ----
    USERS = {}

    @classmethod
    def init_users(cls):
        """从环境变量初始化用户字典"""
        import bcrypt

        cls.USERS = {}

        admin_user = {
            "username": os.environ.get("ADMIN_USERNAME", "admin"),
            "password_hash": os.environ.get("ADMIN_PASSWORD_HASH", ""),
            "role": "admin",
            "email": os.environ.get("ADMIN_EMAIL", ""),
            "phone": os.environ.get("ADMIN_PHONE", ""),
            "balance": getenv_int("ADMIN_BALANCE", 0),
        }
        if admin_user["password_hash"]:
            # 确保密码哈希是 bytes 类型
            if isinstance(admin_user["password_hash"], str):
                admin_user["password_hash"] = admin_user["password_hash"].encode("utf-8")
            cls.USERS[admin_user["username"]] = admin_user

        alice_user = {
            "username": os.environ.get("ALICE_USERNAME", "alice"),
            "password_hash": os.environ.get("ALICE_PASSWORD_HASH", ""),
            "role": "user",
            "email": os.environ.get("ALICE_EMAIL", ""),
            "phone": os.environ.get("ALICE_PHONE", ""),
            "balance": getenv_int("ALICE_BALANCE", 0),
        }
        if alice_user["password_hash"]:
            if isinstance(alice_user["password_hash"], str):
                alice_user["password_hash"] = alice_user["password_hash"].encode("utf-8")
            cls.USERS[alice_user["username"]] = alice_user

        if not cls.USERS:
            raise RuntimeError(
                "未配置任何用户！请设置 ADMIN_PASSWORD_HASH 或 ALICE_PASSWORD_HASH 环境变量"
            )

    # ---- API 密钥 ----
    API_KEY = os.environ.get("API_KEY", "")

    # ---- 安全 ----
    SESSION_TIMEOUT_MINUTES = getenv_int("SESSION_TIMEOUT_MINUTES", 30)
    RATE_LIMIT_PER_MINUTE = getenv_int("RATE_LIMIT_PER_MINUTE", 30)
    LOGIN_MAX_ATTEMPTS = getenv_int("LOGIN_MAX_ATTEMPTS", 5)
    LOGIN_LOCKOUT_MINUTES = getenv_int("LOGIN_LOCKOUT_MINUTES", 10)

    # ---- IP白名单 ----
    ALLOWED_IPS = [
        ip.strip()
        for ip in os.environ.get("ALLOWED_IPS", "127.0.0.1,::1").split(",")
        if ip.strip()
    ]

    # ---- CSRF ----
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = cls.SESSION_TIMEOUT_MINUTES * 60
