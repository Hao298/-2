# 文件上传漏洞攻防 — 修复点与攻击方式对照清单

---

## 一、攻击方式 → 防御代码 完整映射

| # | 攻击方式 | 课堂攻击Payload | 防御措施 | 防御函数/代码位置 | 行号 |
|---|---------|----------------|----------|-------------------|------|
| 1 | **路径穿越** | `../../../etc/passwd.png` | 替换 `../` `./` 为空字符串 | `sanitize_filename()` | L603 |
| 2 | **绝对路径** | `/etc/passwd.png` | 替换 `/` 为空字符串 | `sanitize_filename()` | L605 |
| 3 | **反斜杠** | `..\\..\\shell.png` | 替换 `\\` 为空字符串 | `sanitize_filename()` | L605 |
| 4 | **00截断** | `shell.php\x00.png` | 替换 `\x00` 为空字符串 | `sanitize_filename()` | L605 |
| 5 | **Windows空格绕过** | `shell.php `（末尾空格） | `rstrip(" .")` 清洗末尾空格和点号 | `sanitize_filename()` | L607 |
| 6 | **连续点号** | `shell..png` | `replace("..", ".")` 折叠连续点号 | `sanitize_filename()` | L608-610 |
| 7 | **::$DATA流** | `test.php::$DATA` | `filename.upper()` 检测 `::$DATA` 后清空 | `sanitize_filename()` | L611-613 |
| 8 | **.htaccess配置** | `.htaccess` / `.HtAccess` | 全小写比对后清空，防止上传解析配置文件 | `sanitize_filename()` | L614-616 |
| 9 | **关键要素：全部清洗完后对比** | `clean_name != original_name` | 检测到任何清洗行为即拒绝 | upload() 第①步 | L658-660 |
| 10 | **后缀大小写绕过** | `shell.PHP` / `avatar.pNg` | `ext.lower()` 统一转小写后比对白名单 | upload() 第②步 | L665 |
| 11 | **黑名单绕过** | `.php` `.asp` `.jsp` `.exe` `.py` `.shtml` `.cgi` | **白名单**仅允许 `jpg/jpeg/png/gif`，不在白名单一律拒绝 | upload() 第③步 | L667-669 |
| 12 | **双后缀畸形** | `shell.jpg.php` / `file.png.php3` / `a.jpg.asp` | `split(".")` 检测中间段是否含可执行后缀或图片后缀 | upload() 第④步 | L671-681 |
| 13 | **图片马（GIF/PNG/JPG头+代码）** | `GIF89a<?php system($_GET['cmd']);?>` | 魔数校验：读取前8字节，比对JPEG/PNG/GIF二进制头部签名 | `validate_magic()` | L620-634 |
| 14 | **纯文本伪装图片** | 普通文本文件改后缀 `.png` | 无合法魔数直接拒绝 | `validate_magic()` | L683-686 |
| 15 | **WebShell直接上传** | `<?php eval($_POST['c']);?>` | 恶意特征扫描：17种模式匹配 `<?php` `<?=` `<script` `eval(` `system(` `exec(` `base64_decode(` 等 | `scan_malicious_content()` + `MALICIOUS_PATTERNS` | L553-571 |
| 16 | **短标签WebShell** | `<?=phpinfo()?>` | `<?=` 特征匹配 | `MALICIOUS_PATTERNS` | L555 |
| 17 | **命令执行** | `system('id'); passthru('ls');` | `system(` `passthru(` `shell_exec(` `exec(` 函数名检测 | `MALICIOUS_PATTERNS` | L558-560 |
| 18 | **脚本/事件注入** | `<script>alert(1)</script>` / `onerror=` | `<script` `javascript:` `onerror=` `onload=` 检测 | `MALICIOUS_PATTERNS` | L556-557 |
| 19 | **Content-Type伪造** | `Content-Type: text/html` | 明确非 `image/` 前缀时拒绝 | upload() 第⑥步 | L697-699 |
| 20 | **UUID防止文件覆盖** | 多个同名文件连续上传 | `uuid.uuid4().hex` 重命名，放弃原始文件名 | upload() 第⑦步 | L701-702 |
| 21 | **IP限流防批量Fuzz** | 自动脚本每秒上传N次 | 每IP每分钟最多5次，超出返回"过于频繁" | `check_rate_limit()` | L523-532 / L650-653 |
| 22 | **上传日志审计** | 无日志难以溯源 | 记录到 `logs/upload.log`：时间/IP/用户名/原始名/存储名 | `log_upload()` | L546-550 / L705 |
| 23 | **安全响应头** | 浏览器MIME嗅探执行HTML | `X-Content-Type-Options: nosniff` 禁止脚本执行 | `@app.after_request` | L574-579 |
| 24 | **超大文件DoS** | 上传数GB文件耗尽磁盘 | `MAX_CONTENT_LENGTH = 16MB` 硬上限 | app.config | L16 |
| 25 | **异常捕获防信息泄露** | 触发Python报错暴露路径 | `try-except` 包裹全部逻辑，返回中文"上传失败" | upload() 外层 try | L645-713 |

---

## 二、上传流水线（12步纵深防御）

```
客户端请求上传
  ↓
  ① IP限流检查 (check_rate_limit)              → 防御批量Fuzz
  ↓
  ② 文件名清洗 (sanitize_filename)              → 防御路径穿越/00截断/空格/$DATA/.htaccess
  ↓
  ③ 清洗前后对比 → 不一致则拒绝
  ↓
  ④ 提取后缀 → 转小写 (ext.lower)
  ↓
  ⑤ 白名单校验 (ALLOWED_EXTENSIONS)             → 防御任意后缀上传
  ↓
  ⑥ 双后缀检测 (split(".") 检查中间段)          → 防御 shell.jpg.php
  ↓
  ⑦ 魔数校验 (validate_magic)                    → 防御图片马
  ↓
  ⑧ 恶意内容扫描 (scan_malicious_content)        → 防御WebShell/脚本
  ↓
  ⑨ Content-Type 校验                            → 防御MIME伪造
  ↓
  ⑩ UUID 重命名存储                              → 防御文件覆盖
  ↓
  ⑪ 记录上传日志 (log_upload)                    → 审计溯源
  ↓
  ⑫ try-except 异常捕获 → 中文提示               → 防御信息泄露
  ↓
  响应: 安全响应头 (X-Content-Type-Options)
```

---

## 三、关键代码片段速查

### sanitize_filename() — 路径穿越 + 系统特性清洗

```python
def sanitize_filename(filename):
    filename = filename.replace("../", "").replace("./", "")
    filename = filename.replace("/", "").replace("\\", "").replace("\x00", "")
    filename = filename.rstrip(" .")
    while ".." in filename:
        filename = filename.replace("..", ".")
    if "::$DATA" in filename.upper():
        filename = ""
    if filename.lower() == ".htaccess" or filename.lower().startswith(".htaccess"):
        filename = ""
    return filename
```

### validate_magic() — 魔数校验

```python
MAGIC_NUMBERS = {
    b"\xFF\xD8\xFF":           "jpg/jpeg",
    b"\x89PNG\r\n\x1A\n":     "png",
    b"GIF87a":                 "gif",
    b"GIF89a":                 "gif",
}

def validate_magic(fileobj):
    header = fileobj.read(8)
    fileobj.seek(0)
    for magic, _ in MAGIC_NUMBERS.items():
        if header.startswith(magic):
            return True
    return False
```

### MALICIOUS_PATTERNS — 恶意特征黑名单

```python
MALICIOUS_PATTERNS = [
    b"<?php", b"<?=", b"<?PHP",           # PHP 代码
    b"<script", b"javascript:",            # XSS
    b"onerror=", b"onload=", b"onclick=",  # 事件
    b"eval(", b"base64_decode(", b"system(", b"exec(",
    b"passthru(", b"shell_exec(",          # 命令执行
    b"<?xml", b"<!ENTITY",                 # XXE
    b"#! /bin/sh", b"#! /bin/bash",       # Shell 脚本
    b"<%@", b"Content-Type:",             # ASP / 邮件头
]
```

---

## 四、防御效果验证（curl命令）

```bash
# 路径穿越
curl -F "file=@shell.php" -b cookies.txt "http://192.168.126.133:5000/upload"
# → "文件名包含非法字符或路径穿越特征"

# 图片马（GIF头+php代码）
curl -F "file=@gifshell.php;type=image/gif" -b cookies.txt "http://192.168.126.133:5000/upload"
# → "文件头部魔数不匹配" 或 "文件内容包含恶意特征"

# 双后缀
curl -F "file=@shell.jpg.php;type=image/png" -b cookies.txt "http://192.168.126.133:5000/upload"
# → "不允许的文件类型 .php"

# 正常图片放行
curl -F "file=@avatar.png;type=image/png" -b cookies.txt "http://192.168.126.133:5000/upload"
# → "上传成功！"

# 限流测试（连续6次）
for i in $(seq 1 6); do
  curl -F "file=@avatar.png;type=image/png" -b cookies.txt "http://192.168.126.133:5000/upload"
done
# → 第6次返回 "上传过于频繁，请稍后再试"
```
