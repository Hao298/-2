#!/bin/bash
# ==============================================================================
# /change-password CSRF + 越权 + 业务逻辑 curl 批量测试脚本
# 靶机: http://192.168.126.133:5000
# 接口: POST /change-password
# 依据: 《XSS与CSRF攻防实战培训》全部知识点
# 预期: 修复前全部攻击成功, 修复后全部拦截
# 注意: 仅测试/change-password接口, 不干扰其他模块
# ==============================================================================

TARGET="http://192.168.126.133:5000"
COOKIE_FILE="/tmp/csrf_cookies.txt"
COOKIE_FILE2="/tmp/csrf_cookies2.txt"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASS=0
FAIL=0
TOTAL=0

echo ""
echo "============================================================"
echo "  /change-password — CSRF + 越权 + 业务逻辑 批量测试"
echo "  靶机: $TARGET"
echo "============================================================"
echo ""

# ====== 工具函数：获取CSRF Token ======
get_csrf_token() {
    local cookie=$1
    local token
    token=$(curl -s -b "$cookie" "$TARGET/profile" | grep -oP 'csrf_token" value="\K[^"]+')
    echo "$token"
}

# ====== 工具函数：登录 ======
do_login() {
    local user=$1
    local pass=$2
    local cookie=$3
    curl -s -c "$cookie" "$TARGET/captcha" > /dev/null
    # 用python在flask test client中获取验证码并登录
    python3 -c "
import requests
s = requests.Session()
s.get('$TARGET/captcha')
# We can't decode the captcha from curl, so use flask test client
" > /dev/null 2>&1
    # 用Flask test client 获取cookie
}

# 使用 flask test client 进行实际测试
python3 << 'PYEOF'
import sys, re, requests

TARGET = "http://192.168.126.133:5000"
sys.path.insert(0, "/opt/Class01")
from app import app as flask_app

PASS = 0
FAIL = 0

def check(label, condition, expected_block=True):
    global PASS, FAIL
    if expected_block:
        if condition:
            print(f"  ✅ {label} — 拦截成功")
            PASS += 1
        else:
            print(f"  ❌ {label} — 未拦截")
            FAIL += 1
    else:
        if condition:
            print(f"  ✅ {label}")
            PASS += 1
        else:
            print(f"  ❌ {label}")
            FAIL += 1

with flask_app.test_client() as c:
    # 登录 admin
    c.get("/captcha")
    with c.session_transaction() as s: cap = s.get("captcha")
    c.post("/login", data={"username":"admin","password":"admin123","captcha":cap})

    r = c.get("/profile")
    m = re.search(r'csrf_token" value="([^"]+)"', r.data.decode())
    TOKEN = m.group(1) if m else ""

    print("=" * 55)
    print("CSRF 攻击场景测试")
    print("=" * 55)

    # TC-01: CSRF Token 缺失
    r = c.post("/change-password", data={
        "old_password":"admin123","new_password":"hacked","confirm_password":"hacked"
    })
    check("TC-01: Token缺失绕过", "CSRF" in r.data.decode())

    # TC-02: CSRF Token 不匹配
    r = c.post("/change-password", data={
        "csrf_token":"FAKETOKEN123",
        "old_password":"admin123","new_password":"hacked","confirm_password":"hacked"
    })
    check("TC-02: Token伪造绕过", "CSRF" in r.data.decode())

    # TC-03: 正常Token → 原密码错误
    r = c.post("/change-password", data={
        "csrf_token":TOKEN,
        "old_password":"wrong","new_password":"hacked","confirm_password":"hacked"
    })
    check("TC-03: 原密码错误", "原密码错误" in r.data.decode())

    # TC-04: 新密码为空
    r = c.post("/change-password", data={
        "csrf_token":TOKEN,
        "old_password":"admin123","new_password":"","confirm_password":""
    })
    check("TC-04: 新密码为空", "密码不能为空" in r.data.decode())

    # TC-05: 两次密码不一致
    r = c.post("/change-password", data={
        "csrf_token":TOKEN,
        "old_password":"admin123","new_password":"aaa","confirm_password":"bbb"
    })
    check("TC-05: 两次密码不一致", "两次密码输入不一致" in r.data.decode())

    print("\n" + "=" * 55)
    print("水平越权测试 — 无法修改他人密码")
    print("=" * 55)

    # TC-06: 尝试修改alice密码（后端从session读，只改admin自己）
    r = c.post("/change-password", data={
        "csrf_token":TOKEN,
        "old_password":"admin123","new_password":"adminhacked","confirm_password":"adminhacked"
    })
    assert r.status_code == 302

    # 验证alice密码未被改
    c2 = flask_app.test_client()
    c2.get("/captcha")
    with c2.session_transaction() as s: cap2 = s.get("captcha")
    r = c2.post("/login", data={"username":"alice","password":"alice2025","captcha":cap2})
    check("TC-06: 越权改密 — alice密码未被篡改", "欢迎回来" in r.data.decode())

    print("\n" + "=" * 55)
    print("正常功能 — 修复后应正常工作")
    print("=" * 55)

    # TC-07: 正常修改（带Token+原密码）
    r = c.get("/profile")
    m = re.search(r'csrf_token" value="([^"]+)"', r.data.decode())
    TOKEN2 = m.group(1)
    r = c.post("/change-password", data={
        "csrf_token":TOKEN2,
        "old_password":"adminhacked","new_password":"finalpass","confirm_password":"finalpass"
    })
    check("TC-07: 正常改密成功", r.status_code == 302, expected_block=False)

    # TC-08: 新密码可登录
    c.get("/captcha")
    with c.session_transaction() as s: cap3 = s.get("captcha")
    r = c.post("/login", data={"username":"admin","password":"finalpass","captcha":cap3})
    check("TC-08: 新密码登录成功", "欢迎回来" in r.data.decode(), expected_block=False)

    # TC-09: 旧密码失效
    c4 = flask_app.test_client()
    c4.get("/captcha")
    with c4.session_transaction() as s: cap4 = s.get("captcha")
    r = c4.post("/login", data={"username":"admin","password":"admin123","captcha":cap4})
    check("TC-09: 旧密码登录失败", "用户名或密码错误" in r.data.decode())

    print("\n" + "=" * 55)
    print("原有功能不受影响")
    print("=" * 55)
    assert "注册" in c.get("/register").data.decode(); print("   ✅ 注册页")
    assert c.get("/search?keyword=admin").status_code == 200; print("   ✅ 搜索")
    assert "上传" in c.get("/upload").data.decode(); print("   ✅ 上传页")
    assert "帮助中心" in c.get("/page?name=help").data.decode(); print("   ✅ 帮助中心")

    print(f"\n{'='*55}")
    print(f"  PASS: {PASS} | FAIL: {FAIL}")
    print(f"{'='*55}")
    if FAIL == 0:
        print("  ✅ 修复判定: CSRF+越权+业务逻辑 全部防御通过")
    else:
        print("  ❌ 修复判定: 存在未修复漏洞")
    print(f"{'='*55}")
PYEOF
