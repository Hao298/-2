# SQL注入与WAF绕过专项实训报告

---

## 一、基础信息

| 项目 | 内容 |
|------|------|
| **实训项目** | SQL注入漏洞挖掘与WAF绕过防御实战 |
| **实训学员** | 大二网络安全专业学生 |
| **实训日期** | 2026-07-20 |
| **实训环境** | Kali Linux 2026.2 / Python Flask + SQLite / Burp Suite |
| **靶机地址** | 192.168.126.133:5000 |
| **项目位置** | /opt/Class01/ |
| **核心文件** | app.py / templates/*.html / static/css/style.css |

---

## 二、实验目的

1. 理解字符型联合查询注入的闭合原理与UNION SELECT回显机制
2. 掌握布尔盲注、时间盲注的逐字猜解与SLEEP延时探测手法
3. 实操WAF绕过技术：换行符、内联注释、双空格、双层URL编码绕过
4. 掌握参数化查询从根源防御SQL注入的底层原理
5. 学习纵深防御体系：WAF过滤 + 参数化查询 + 输出脱敏 + 超时保护
6. 体验AI批量Fuzz测试语句对WAF的冲击与长度截断防御效果

---

## 三、今日实训三阶段工作概述

### 第一阶段：课堂理论学习 + Burp渗透测试（09:00-11:00）

上午课堂学习了四类SQL注入的攻击原理与手工注入7步探测流程：

```
Step1: 单引号闭合探测  ' → 报错
Step2: 注释绕过       '-- → 消除尾部约束
Step3: 列数探测       ' ORDER BY N--
Step4: 联合查询回显   ' UNION SELECT 1,2,3...
Step5: 条件探测       ' AND 1=1-- / OR '1'='1
Step6: 系统变量查询   ' UNION SELECT @@version--
Step7: 元数据读取     ' UNION SELECT table_name FROM information_schema.tables--
```

使用Burp Suite对靶机登录/搜索接口进行手工注入测试，搜索接口存在f-string拼接漏洞，Payload成功回显数据库内容。

**Burp抓包截图（POC）：**
```
GET /search?keyword=admin' UNION SELECT 1,2,3,4-- HTTP/1.1
Host: 192.168.126.133:5000
```
响应返回4列数据，确认注入点可用。

### 第二阶段：分步漏洞改造（14:00-16:00）

针对已发现的注入漏洞，分四轮改造：

| 轮次 | 改造内容 | 核心变更 |
|------|----------|----------|
| **第1轮** | 参数化查询改造 | 删除全部f-string拼接，替换为 `?` 占位符 |
| **第2轮** | WAF过滤层 | 新增 `input_clean()` 全局清洗函数 |
| **第3轮** | 验证码+鉴权+脱敏 | 新增 `/captcha`、搜索登录校验、输出脱敏 |
| **第4轮** | 盲注专项防护 | 新增 `query_with_timeout()` 超时保护 + 数字型校验 |

### 第三阶段：盲注补充防护 + 最终测试（16:00-17:30）

- 新增 `database()`、`/*+` Oracle注释等关键字到过滤列表
- 新增 `field_type="integer"` 纯整数校验，阻断 `id=3-1` 运算探测
- 新增双层URL编码解码 `_url_decode()` 两次unquote
- 新增 `signal.alarm(2)` SQL执行超时保护
- 所有路由回归测试通过

---

## 四、漏洞汇总表格

| 漏洞编号 | 漏洞类型 | 风险等级 | 攻击入口 | 是否修复 |
|----------|----------|----------|----------|----------|
| VUL-001 | 字符型联合查询注入 | **高危** | `/search?keyword=` | ✅ 已修复 |
| VUL-002 | 字符型联合查询注入 | **高危** | `/register` POST | ✅ 已修复 |
| VUL-003 | 布尔盲注（AND/OR探测） | **中危** | `/search` | ✅ 已修复 |
| VUL-004 | 时间盲注（SLEEP延时） | **中危** | `/search` | ✅ 已修复 |
| VUL-005 | WAF换行绕过（%0a） | **高危** | 全部GET/POST入口 | ✅ 已修复 |
| VUL-006 | WAF注释绕过（/**/） | **高危** | 全部GET/POST入口 | ✅ 已修复 |
| VUL-007 | WAF双层编码绕过（%2527） | **高危** | 全部GET/POST入口 | ✅ 已修复 |
| VUL-008 | 明文密码泄露 | **中危** | 首页用户信息卡片 | ⚠️ 保留（课堂演示） |
| VUL-009 | 无验证码暴力破解 | **中危** | `/login` POST | ✅ 已修复 |
| VUL-010 | 搜索接口未授权访问 | **中危** | `/search` | ✅ 已修复 |
| VUL-011 | 纯数字邮箱注册500报错 | **低危** | `/register` | ✅ 已修复 |
| VUL-012 | 数字型运算注入（id=3-1） | **低危** | 潜在整型参数 | ✅ 已修复 |

---

## 五、分项漏洞原理 + POC复现 + 分层修复

### 5.1 VUL-001 搜索接口字符型联合查询注入

#### 漏洞原理

原始代码使用f-string拼接SQL语句，用户输入直接嵌入查询字符串，攻击者可闭合前引号后执行任意SQL语句：

```python
# 原始危险代码（v1.0）
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
print(f"[SQL] {sql}")
results = c.execute(sql).fetchall()
```

攻击者输入 `admin' UNION SELECT 1,2,3,4--` 后，实际执行的SQL变为：

```sql
SELECT id, username, email, phone FROM users WHERE username LIKE '%admin' UNION SELECT 1,2,3,4--%' OR email LIKE '%...%'
```

`'--` 闭合前引号 + 注释掉后续语句，UNION SELECT成功叠加回显。

#### POC复现

**Burp Suite Payload：**
```
GET /search?keyword=admin' UNION SELECT 1,2,3,4-- HTTP/1.1
```

**curl测试命令：**
```bash
# 注入验证 —— 原始漏洞版本返回了 1,2,3,4
curl -sb cookies.txt "http://192.168.126.133:5000/search?keyword=%27%20UNION%20SELECT%201,2,3,4--"
# 响应中包含 "2" "3" "4" 字样，确认注入成功
```

**系统变量查询：**
```bash
curl -sb cookies.txt "http://192.168.126.133:5000/search?keyword=%27%20UNION%20SELECT%20@@version,2,3,4--"
```

#### 分层修复方案

| 层级 | 修复措施 | 代码位置 | 说明 |
|------|----------|----------|------|
| **底层根治** | 参数化查询 `?` 占位符 | app.py L351-353 | 从协议层分离SQL代码与数据，单引号闭合彻底失效 |
| **辅助防护1** | `input_clean(keyword, "keyword")` | app.py L341 | 前置过滤单引号、关键字union/select、注释符 |
| **辅助防护2** | WAF黑名单 `SQL_KEYWORDS` | app.py L50-63 | 52个敏感关键字全词正则匹配 |
| **辅助防护3** | `COMMENT_PATTERNS` 注释符检测 | app.py L73-77 | `--` `#` `/**/` 全部拦截 |
| **辅助防护4** | 搜索登录鉴权 | app.py L332-333 | 未登录302跳转，禁止匿名Fuzz |
| **辅助防护5** | 输出脱敏 | app.py L199-225 | 即使注入成功，回显数据被脱敏 |
| **辅助防护6** | `query_with_timeout()` 超时 | app.py L176-188 | SLEEP等延时函数2秒超时截断 |

**修复后代码：**
```python
# 修复代码（v5.0）
keyword = input_clean(keyword, "keyword", KEYWORD_MAX_LEN)  # WAF前置过滤
like_pattern = f"%{keyword}%"
rows = query_with_timeout(c,
    "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
    (like_pattern, like_pattern)
).fetchall()
results = [(row[0], mask_username(row[1]), mask_email(row[2]), mask_phone(row[3])) for row in rows]
# 输出: (2, "a***", "a***@example.com", "139****9001")
```

---

### 5.2 VUL-003 / VUL-004 布尔盲注 + 时间盲注

#### 漏洞原理

布尔盲注利用 `AND 1=1` 与 `AND 1=2` 页面差异逐字猜解数据；时间盲注通过 `SLEEP(5)` 延时判断条件真假。

**原始代码f-string拼接盲注探测示例：**
```sql
-- 布尔盲注探测
SELECT ... WHERE username LIKE '%admin' AND 1=1--%' ...
-- 页面正常返回 → 注入成立

-- 时间盲注探测  
SELECT ... WHERE username LIKE '%admin' AND IF(1=1,SLEEP(5),0)--%' ...
-- 响应延迟5秒 → 注入成立
```

#### 分层修复方案

| 层级 | 修复措施 | 代码位置 | 说明 |
|------|----------|----------|------|
| **底层根治** | 参数化查询 | L351-353 | `?` 占位符使 `AND 1=1` 成为纯字符串，不解析为SQL |
| **WAF拦截** | `SQL_KEYWORDS` | L50 L56 L57 | `and` `or` `if` `sleep` `benchmark` `delay` `length` `substr` 全部关键字拦截 |
| **超时兜底** | `query_with_timeout()` | L176-188 | `signal.alarm(2)` 2秒硬上限，SLEEP(5)被SIGALRM信号截断 |
| **异常捕获** | `try-except` 中文提示 | L364-368 | 超时报错不暴露SQL细节 |

**修复后效果验证：**
```python
# 时间盲注 — 关键字拦截 + 超时防御
def _timeout_handler(signum, frame):
    raise SQLTimeoutError("SQL 执行超时（检测到疑似 SLEEP 延时注入）")

def query_with_timeout(cursor, sql, params=None, timeout=SQL_TIMEOUT):
    signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(timeout)          # 设置2秒定时炸弹
    try:
        result = cursor.execute(sql, params)
        signal.alarm(0)             # 正常返回取消闹钟
        return result
    except SQLTimeoutError:
        signal.alarm(0)
        raise                       # 超时抛出，前端显示中文提示
```

---

### 5.3 VUL-005 / VUL-006 / VUL-007 WAF变形绕过

#### 漏洞原理

攻击者通过特殊字符变形绕过关键字黑名单检测：

| 绕过手法 | 原始Payload | 变形Payload | 绕过目标 |
|----------|-------------|-------------|----------|
| 换行绕过 | `admin' OR 1=1--` | `admin%0aOR%0a1=1--` | `or` 不在同一行 → 正则漏检 |
| 内联注释 | `UNION SELECT` | `UN/**/ION SEL/**/ECT` | 关键字被分割 → 全词匹配失效 |
| 双空格 | `OR 1=1` | `OR  1=1` | \bOR\b 误用空格token通过 |
| 双层编码 | `'` | `%2527` → 解码一次 `%27` → 再解码 `'` | 单层解码后仍是编码态 → 漏检 |

#### POC复现

```bash
# %0a 换行绕过（原始WAF未拦截时）
curl -sb cookies.txt "http://192.168.126.133:5000/search?keyword=admin%0aOR%0a1=1--"

# /*!*/ 内联注释绕过
curl -sb cookies.txt "http://192.168.126.133:5000/search?keyword=admin'%20UNION%20/*!*/SELECT%201,2,3,4--"

# %2527 双层URL编码（第一次解码%25→%，第二次解码%27→'）
curl -sb cookies.txt "http://192.168.126.133:5000/search?keyword=admin%2527"
```

#### 分层修复方案

| 层级 | 绕过手法 | 修复代码 | 位置 | 原理 |
|------|----------|----------|------|------|
| **底层** | `%0a` `%0d` | `WHITESPACE_CHARS` → `_detect_whitespace_obfuscation()` | L66-68 L149-158 | URL解码后检测 `\n` `\r` `\t` `\x0b` `\x0c` `\xa0` |
| **底层** | `/**/` `/*!*/` | `COMMENT_PATTERNS` 循环检测 | L73-77 L100 | `"/**/"` `"/*!"` `"/*"` `"*/"` `"/*+"` 6种注释模式 |
| **底层** | 双空格 | `_detect_whitespace_obfuscation()` | L155-156 | `"  "` 检测两个及以上连续空格 |
| **底层** | `%2527` 双层编码 | `_url_decode()` 两次 unquote | L134-142 | 循环解码2次，最终得到原始字符重新检测 |
| **底层** | `--` `#` `;` | `COMMENT_PATTERNS` | L73-77 | 行注释 + 堆叠查询全拦截 |
| **底层** | 反引号 `\`` | 引号检测 + `COMMENT_PATTERNS` | L75 L110-112 | `"``"` 双通道拦截 |
| **辅助** | 超长Fuzz | `input_clean()` 长度截断 | L86-88 | `>400` 拒绝 + `[:max_len]` 安全截断 |

**修复后效果：**
```python
# 双层URL解码防御
def _url_decode(s):
    decoded = s
    for _ in range(2):                     # 两次解码拦截双重编码
        prev = decoded
        decoded = urllib.parse.unquote(decoded)
        if decoded == prev:
            break
    return decoded

# 空表符检测
def _detect_whitespace_obfuscation(text):
    for ch in text:
        if ch in WHITESPACE_CHARS and ch != " ":
            raise ValueError(f"WAF 拦截：检测到非法空白符 {repr(ch)}")
    if "  " in text:
        raise ValueError("WAF 拦截：检测到连续空白符")
```

---

### 5.4 VUL-012 数字型运算注入

#### 漏洞原理

数字型参数如果只做 `is not None` 检查而不做类型校验，攻击者可传入 `3-1` 利用SQL内部隐式类型转换探测数据库：

```sql
-- 传入 id=3-1，SQL解析为
SELECT * FROM users WHERE id = 3-1     -- 等同于 WHERE id = 2
```

#### 修复措施

新增 `field_type="integer"` 严格纯整数校验：

```python
elif field_type == "integer":
    if not re.match(r'^\d+$', value):
        raise ValueError("WAF 拦截：数字参数包含非法字符（拒绝算术表达式）")
```

| 输入 | 校验结果 |
|------|----------|
| `42` | ✅ 纯整数通过 |
| `3-1` | ❌ 拦截 |
| `3+1` | ❌ 拦截 |
| `3*2` | ❌ 拦截 |
| `3/1` | ❌ 拦截 |
| `3.5` | ❌ 拦截 |

---

### 5.5 VUL-009 无验证码暴力破解

#### 漏洞原理

登录/注册/找回密码接口无验证码校验，攻击者可自动化工具批量爆破密码。

#### 修复措施

新增 `/captcha` 图形验证码接口（PNG图片 + session比对）：

| 路由 | 验证码校验位置 |
|------|---------------|
| `/login` POST | L270-272 |
| `/register` POST | L339-341 |
| `/forget_pwd` POST | L438-440 |

```python
# 验证码生成（4位随机数字 + 干扰线 + 噪点）
@app.route("/captcha")
def captcha():
    code = str(random.randint(1000, 9999))
    session["captcha"] = code
    # 绘制120×40 PNG图片...
    
# 表单校验
if session.get("captcha") != captcha_input:
    return render_template("login.html", error="验证码错误")
```

---

### 5.6 VUL-010 搜索接口未授权访问

#### 漏洞原理

搜索接口未做登录检查，匿名用户可直接访问 `/search?keyword=xxx` 进行批量Fuzz拖库。

#### 修复措施

```python
@app.route("/search")
def search():
    username = session.get("username")
    if not username or username not in USERS:
        return redirect("/login")          # 未登录 → 302跳转
```

---

### 5.7 VUL-008 / VUL-011 信息泄露与异常处理

| 漏洞 | 问题 | 修复 |
|------|------|------|
| 明文密码 | 首页显示用户密码 | ⚠️ 课堂演示保留，生产必改bcrypt |
| 纯数字邮箱500 | SQLite `UNIQUE` 约束未捕获 | `try-except IntegrityError` 中文提示 |
| SQL报错信息 | `OperationalError` 暴露原始错误 | 统一捕获返回"数据库异常" |

---

## 六、踩坑故障记录

### 坑1：debug=True 导致数据库路径错位

**现象：** Flask debug模式会重载两次子进程，`os.makedirs("data")` 相对路径从 `/opt/Class01/` 偏移到 `/root/`，两个目录各有一个 `users.db`，注册数据在 `/root/data/` 而搜索读 `/opt/Class01/data/`，互相无法查到。

**解决：** 使用 `BASE_DIR = os.path.dirname(os.path.abspath(__file__))` 绝对路径拼接。

---

### 坑2：搜索页未传递 user 信息 → 显示"请先登录"

**现象：** 搜索路由返回 `index.html` 时没有传 `user=user_info` 参数，虽然session里有username，但模板判断 `{% if username and user %}` 失败，已登录用户看到"请先登录"。

**解决：** search() 中补充：
```python
username = session.get("username")
user_info = None
if username and username in USERS:
    user_info = USERS[username]
```

---

### 坑3：单引号转义 `"'"` 后仍偶发500

**现象：** 使用 `.replace("'", "''")` 做转义，但输入 `\` 反斜杠时存在转义逃逸：`\'` → `''` 后变成 `\''` 导致SQL语法错误。

**解决：** 最终方案不是修转义，而是彻底删除f-string拼接，改用参数化查询 `?` 占位符，引号问题从根源消失。

---

### 坑4：WAF关键字 `or` 误杀正常用户名

**现象：** `SQL_KEYWORDS` 中 `"or"` 全词匹配时，用户注册 `admin` 没影响，但用户名 `worker` 中的 `or` 被拦截。

**解决：** 使用 `\b` 正则全词匹配而非 `in` 字符串包含：
```python
# 正确：全词匹配
if re.search(r'\b' + re.escape("or") + r'\b', "worker")  # False → 不拦截
# 错误：字符串包含
if "or" in "worker":  # True → 误杀
```

---

### 坑5：搜索结果脱敏断言失败

**现象：** 测试时断言 `assert "139****0001" in html` 失败，实际脱敏结果是 `139****9001`（alice手机号后4位是9001，不是0001）。

**解决：** 测试数据写错了，核对数据库后修正断言。

---

## 七、修复前后对比表格

| 对比项 | 修复前（v1.0） | 修复后（v5.0） |
|--------|---------------|---------------|
| **SQL查询方式** | f-string拼接 | 参数化 `?` 占位符 |
| **引号处理** | `.replace("'", "''")` | 不需要（参数化自动处理） |
| **注册输入** | 无校验直接拼接 | `input_clean()` + 邮箱格式校验 |
| **搜索访问** | 无需登录 | 登录鉴权 + 输出脱敏 |
| **验证码** | 无 | `/captcha` PNG验证码 |
| **关键字过滤** | 无 | 52个SQL关键字全词正则 |
| **注释过滤** | 无 | 6种注释模式 + 空白符 |
| **URL解码** | 单层解码 | 双层解码防双重编码绕过 |
| **SQL超时** | 无 | `signal.alarm(2)` 2秒上限 |
| **数字校验** | 无类型区分 | `integer`/`phone`/`keyword` 分离校验 |
| **错误处理** | 抛出500 | `try-except` 中文提示 |
| **控制台** | `print(f"[SQL] {sql}")` 泄露 | 全部删除 |

---

## 八、复测用例

### 8.1 正常业务流程（确认不改坏）

| 用例 | 操作 | 预期结果 |
|------|------|----------|
| TC-01 | 注册新用户 | 302跳转登录页 |
| TC-02 | admin登录 | 显示"欢迎回来，admin！" |
| TC-03 | 搜索关键词`alice` | 搜索结果表格含用户名/邮箱/手机（脱敏） |
| TC-04 | 找回密码+重置 | 302跳转登录页提示"密码重置成功" |
| TC-05 | 登出后访问首页 | 显示"请先登录" |

### 8.2 注入攻击阻断（确认拦截生效）

| 用例 | Payload | 预期拦截结果 |
|------|---------|-------------|
| TC-06 | `admin'` | WAF拦截：单引号 |
| TC-07 | `admin'--` | WAF拦截：注释符 |
| TC-08 | `admin' ORDER BY 1--` | WAF拦截：ORDER BY |
| TC-09 | `admin' UNION SELECT 1,2,3,4--` | WAF拦截：UNION SELECT |
| TC-10 | `admin' AND 1=1--` | WAF拦截：AND + 单引号 |
| TC-11 | `admin' UNION SELECT @@version--` | WAF拦截：@@version |
| TC-12 | `admin' UNION SELECT database()--` | WAF拦截：database( |
| TC-13 | `admin' UNION SELECT * FROM information_schema.tables--` | WAF拦截：information_schema |

### 8.3 WAF绕过变形（确认各种变形均被拦截）

| 用例 | 绕过手法 | 预期拦截结果 |
|------|---------|-------------|
| TC-14 | `admin%0aOR%0a1=1` | WAF拦截：非法空白符 |
| TC-15 | `admin/**/OR/**/1=1` | WAF拦截：注释符 |
| TC-16 | `admin/*!*/` | WAF拦截：注释符 |
| TC-17 | `admin%2527` 双层编码 | WAF拦截：单引号（双层解码后） |
| TC-18 | `admin  OR  1=1` 双空格 | WAF拦截：连续空白符 |
| TC-19 | `` admin` `` 反引号 | WAF拦截：非法引号 |
| TC-20 | `a`*500 超长Fuzz | WAF拦截：输入超长 |

### 8.4 辅助防御（确认配套机制生效）

| 用例 | 操作 | 预期结果 |
|------|------|----------|
| TC-21 | 验证码错误 | 提示"验证码错误"，不执行后续逻辑 |
| TC-22 | 未登录访问`/search` | 302跳转到`/login` |
| TC-23 | 搜索手机号完整显示 | 页面显示`139****9001`，非完整号码 |
| TC-24 | 手机号输入字母 | 提示"手机号格式错误" |
| TC-25 | `id=3-1` 运算式 | WAF拦截：数字参数含非法字符 |

---

## 九、总结感悟

### 9.1 理论与实操的差距

课堂上学了"SQL注入原理"以为理解了，实际动手才发现差距很大：

- **注入点发现**：课堂demo用现成的sqlmap一把梭，手工测时连搜索框是GET还是POST都要试半天
- **Payload构造**：学了闭合方式，但在Burp里反复调试单引号/括号/注释的空格位置才成功回显
- **WAF绕过**：本以为换行绕过是"加个%0a就行"，结果发现会被URL解码检测加双空格检测串行拦截，远超预期

### 9.2 纵深防御的启示

修复过程让我真正理解了"纵深防御"不是概念而是必须：

```
输入层     →  input_clean() WAF过滤（长度截断/关键字/注释/空白符）
↓
数据库层   →  参数化查询 ? 占位符（SQL注入的根源阻断）
↓
执行层     →  signal.alarm(2) 超时保护（SLEEP时间盲注的兜底）
↓
输出层     →  mask_phone/email/username 脱敏（即使注入成功也拿不到完整数据）
↓
异常层     →  try-except 中文提示（不暴露任何SQL细节）
```

任何单层防护都有被绕过的可能，5层叠加后攻击者的成本呈指数上升。

### 9.3 AI Fuzz的冲击

用AI生成了500+字符的超长Fuzz语句手动测试，瞬间理解了为什么需要长度截断。不加限制的话，几行Python脚本就能让WAF在正则回溯中耗尽CPU。`>400直接拒绝 + [:100]安全截断` 这个策略最简单但也最有效。

### 9.4 后续学习方向

- 本次只覆盖了GET/POST参数注入，HTTP Header注入和二次注入还需要学习
- MySQL和SQLite语法有差异，生产常见MySQL的 `-- ` 带空格注释需要额外适配
- 图灵完备的WAF（如modsecurity CRS规则集）在绕过手法上还有大量进阶内容

---

## 十、生产优化建议

### 10.1 密码安全

```python
# 当前（仅课堂演示）
USERS["admin"]["password"] = "admin123"        # 明文

# 生产必须改为
import bcrypt
hashed = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
USERS["admin"]["password"] = hashed
```

### 10.2 验证码升级

当前4位纯数字验证码暴力破解概率为1/10000，生产建议：
- 增加字母混合（6位字母+数字）
- 加入扭曲/旋转/粘连
- Redis存储验证码并设置60秒过期

### 10.3 CSRF防护

当前表单没有CSRF Token，生产建议：
```python
import secrets
@app.before_request
def generate_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
```

### 10.4 HTTPS强制

```python
# 生产环境必须
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

### 10.5 速率限制

```python
# 使用 Flask-Limiter 防止暴力破解
from flask_limiter import Limiter
limiter = Limiter(app, key_func=lambda: request.remote_addr)
@login.route("/login", methods=["POST"])
@limiter.limit("5 per minute")   # 每分钟最多5次登录尝试
def login():
    ...
```

### 10.6 日志审计

```python
# 记录所有WAF拦截事件到独立文件
import logging
waf_logger = logging.getLogger("waf")
waf_handler = logging.FileHandler("/var/log/waf_blocks.log")
waf_logger.addHandler(waf_handler)

def waf_filter(value):
    ...
    raise ValueError("WAF 拦截...")
    waf_logger.warning(f"[WAF_BLOCK] {request.remote_addr} - {value}")
```

---

## 附录A：项目文件结构

```
/opt/Class01/
├── app.py                  # 主程序（v5.0 完整防护版）
├── data/
│   └── users.db            # SQLite数据库
├── templates/
│   ├── base.html           # 基础模板（导航栏含注册入口）
│   ├── index.html          # 首页（搜索框+搜索结果脱敏表格）
│   ├── login.html          # 登录页（验证码+忘记密码链接）
│   ├── register.html       # 注册页（邮箱JS校验+验证码）
│   └── forget_pwd.html     # 找回密码（两步表单+验证码）
├── static/
│   └── css/
│       └── style.css       # 样式文件
└── report.md               # 本报告
```

## 附录B：WAF过滤规则速查

| 过滤层次 | 规则数 | 核心检测项 |
|----------|--------|-----------|
| 长度截断 | 2条 | `>400拒绝` `[:max_len]截断` |
| 空白符 | 7种 | `\t \n \r \x0b \x0c \xa0 双空格` |
| 注释符号 | 6种 | `/**/ /*! /*+ -- # ; */` |
| 引号 | 3种 | `' " \`` |
| SQL关键字 | 52个 | `union select or and order by group_concat ...` |
| 类型校验 | 4种 | `string / digit / integer / phone / keyword` |

---

*报告人：大二网络安全实训生*
*日期：2026年7月20日*
