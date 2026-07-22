# 个人中心与充值模块 — 攻击路径与防御代码对照清单

---

## 一、水平越权（IDOR）漏洞

### 1.1 漏洞原理

水平越权（Insecure Direct Object Reference）是指应用程序在访问资源时直接使用用户提供的参数（如 `user_id`），但未验证该参数是否属于当前登录用户。攻击者只需修改 URL 中的 `user_id` 参数值即可访问其他用户的敏感信息。

### 1.2 攻击路径

```
攻击者登录自己的账号 (admin)
  ↓
浏览 /profile?user_id=1           → 看到 admin 本人的资料（正常）
  ↓
修改 URL 参数为 /profile?user_id=2  → 看到 alice 的手机号、余额（越权成功！）
  ↓
使用 Burp Intruder 批量枚举 user_id=1~1000  → 批量拖取所有用户资料
```

### 1.3 Burp POC 载荷

**原始漏洞请求（v1.0 — 未修复）：**
```http
GET /profile?user_id=2 HTTP/1.1
Host: 192.168.126.133:5000
Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0...
```

**Burp Intruder 批量枚举配置：**
```
GET /profile?user_id=§1§ HTTP/1.1    ← Payload: 1~1000 数字枚举
```

**curl 命令：**
```bash
# 越权查看 alice 资料（原始漏洞版本）
curl -b cookies.txt "http://192.168.126.133:5000/profile?user_id=2"

# 批量越权探测
for i in {1..100}; do
  curl -b cookies.txt "http://192.168.126.133:5000/profile?user_id=$i"
done
```

### 1.4 分层修复方案

| 层级 | 修复措施 | 代码 | 行号 | 防御原理 |
|------|----------|------|------|----------|
| **底层根治** | user_id 只从 session 读取，拒绝前端传参 | `cur_username = session.get("username")` | L772 | 服务端身份凭证无法被篡改 |
| **底层根治** | SQL 查询不再使用 user_id，改用 username | `SELECT ... WHERE username = ?` | L779 | 彻底消除参数代入路径 |
| **辅助防护** | 手机号、邮箱脱敏 | `mask_phone(phone)` / `mask_email(email)` | L792-793 | 即使越权发生，敏感数据脱敏 |
| **辅助防护** | IDOR 探测特征过滤 | `filter_idor_probe()` + `IDOR_PROBE_PATTERNS` | L607-625 | 拦截批量探测前的侦察行为 |

```python
# 修复前（v1.0）—— 直接信任 URL 参数
user_id = request.args.get("user_id", "")
row = c.execute("SELECT ... WHERE id = ?", (user_id,)).fetchone()
# → 攻击者将 user_id=2 改为 user_id=3 即可越权看其他人

# 修复后（v5.0）—— 拒绝前端传入，从 session 读取
cur_username = session.get("username")                # session 不可伪造
row = c.execute("SELECT ... WHERE username = ?", (cur_username,)).fetchone()
# → URL 参数被完全忽略，只查当前登录用户
```

### 1.5 修复后验证

| 操作 | 预期结果 |
|------|----------|
| 登录 admin 访问 `/profile` | 显示 admin 本人信息 |
| 登录 admin 访问 `/profile?user_id=2` | 仍显示 admin 本人（参数被忽略） |
| 未登录访问 `/profile` | 302 跳转登录页 |
| 登录 alice 访问 `/profile` | 显示 alice 本人信息 |

---

## 二、负数金额业务逻辑漏洞

### 2.1 漏洞原理

充值接口未对 `amount` 参数做正负校验，攻击者可提交负数金额实现"反向转账"——从自己账户余额中扣减任意数值（相当于盗取平台资金）。

### 2.2 攻击路径

```
攻击者登录账号 (admin, 余额 ¥99999)
  ↓
构造充值请求 amount=-50000
  ↓
服务器执行: balance = 99999 + (-50000) = 49999
  ↓
攻击者账户凭空增加 (或扣减) 任意金额
  ↓
提取或转移资金：实际损失 ±50000
```

### 2.3 Burp POC 载荷

```http
POST /recharge HTTP/1.1
Host: 192.168.126.133:5000
Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0...
Content-Type: application/x-www-form-urlencoded

user_id=1&amount=-50000
```

**curl 命令：**
```bash
# 原始漏洞版本：负数扣减余额
curl -b cookies.txt -X POST \
  -d "user_id=1&amount=-50000" \
  "http://192.168.126.133:5000/recharge"

# 超小金额刮削（0.001 元 × 1000000 次 = 1000 元）
curl -b cookies.txt -X POST \
  -d "user_id=1&amount=0.001" \
  "http://192.168.126.133:5000/recharge"

# 超巨额充值（突破系统上限）
curl -b cookies.txt -X POST \
  -d "user_id=1&amount=9999999999" \
  "http://192.168.126.133:5000/recharge"
```

### 2.4 分层修复方案

| 层级 | 防御措施 | 代码 | 行号 | 拦截输入 |
|------|----------|------|------|----------|
| **底层-格式校验** | 正则 `^\d+(\.\d{1,2})?$` | `re.match(...)` | L834 | 拦截 `abc` `1e5` `0x10` `1.234` `--100` `1\n00` |
| **底层-正负校验** | `amount <= 0` 拦截 | `if amount <= 0: return error` | L838-840 | 拦截 -50000、0 |
| **底层-下限拦截** | `amount < RECHARGE_MIN` | `RECHARGE_MIN = 0.01` | L53, L842-843 | 拦截 0.001 |
| **底层-上限拦截** | `amount > RECHARGE_MAX` | `RECHARGE_MAX = 100000` | L54, L844-845 | 拦截 100001+ |
| **辅助-身份固化** | session 读取，拒绝前端 user_id | `cur_username = session.get(...)` | L813 | 防修改充值对象 |
| **辅助-限流** | 每分钟最多 10 次 | `check_rate_limit(ip, 10, 60)` | L817-821 | 防批量 Fuzz |
| **辅助-日志** | 每笔变动记录日志 | `log_balance_change(...)` | L851 | 异常资金溯源 |
| **辅助-异常捕获** | try-except 中文提示 | `except Exception as e:` | L854-855 | 防信息泄露 |

```python
# 修复后完整充值校验流水线
amount_str = request.form.get("amount", "").strip()
if not amount_str:                              # 非空检查
    return "金额不能为空"
if not re.match(r'^\d+(\.\d{1,2})?$', amount_str):  # 格式检查（拦截字母、符号、换行）
    return "金额格式错误"
amount = float(amount_str)
if amount <= 0:                                 # 正负 + 0 检查
    return "金额必须大于 0"
if amount < RECHARGE_MIN:                       # 下限检查
    return "最低充值 0.01 元"
if amount > RECHARGE_MAX:                       # 上限检查
    return "最高充值 100000 元"
# 全部通过 → 执行充值 + 记录日志
```

### 2.5 修复后验证

| 输入 | 拦截原因 | 结果 |
|------|----------|------|
| `-500` | 负数 | ❌ 拦截 |
| `0` | 等于 0 | ❌ 拦截 |
| `0.001` | 低于最低 0.01 | ❌ 拦截 |
| `100001` | 超过最高 100000 | ❌ 拦截 |
| `abc` | 含字母 | ❌ 拦截 |
| `1.234` | 超两位小数 | ❌ 拦截 |
| `1e5` | 科学计数法 | ❌ 拦截 |
| `1\n00` | 含换行符 | ❌ 拦截 |
| `--100` | 含注释符号 | ❌ 拦截 |
| `0x10` | 十六进制 | ❌ 拦截 |
| `50` | 正常充值 | ✅ 通过 + 余额更新 + 日志记录 |

---

## 三、防御矩阵总览

| 漏洞类型 | 攻击入口 | 攻击手法 | Burp POC | 防御层数 | 修复位置 |
|----------|----------|----------|----------|----------|----------|
| **水平越权 IDOR** | `/profile?user_id=N` | 遍历 user_id 查看他人资料 | `GET /profile?user_id=2` | 4 层 | L768-800 + L792-793 + L607-625 |
| **水平越权 IDOR** | `/recharge` 表单 | 篡改 user_id 为他人充值 | `user_id=2&amount=100` | 3 层 | L813-814 + L817-821 |
| **负数金额** | `/recharge` POST | amount=-50000 扣减余额 | `amount=-50000` | 5 层 | L831-845 |
| **超小额刮削** | `/recharge` POST | amount=0.001 可无限请求 | `amount=0.001` | 4 层 | L842-843 + L817-821 |
| **超巨额充值** | `/recharge` POST | amount=9999999999 | `amount=9999999999` | 3 层 | L844-845 |
| **畸形载荷** | `/recharge` POST | 字母/符号/换行/科学计数 | `amount=1e5` | 3 层 | L834-835 |
| **批量枚举** | Burp Intruder | Fuzz user_id 1~1000 | `§1§` → 1000 次 | 3 层 | L607-625 + L817-821 |
| **信息泄露** | `/profile` 响应 | 手机号/邮箱明文暴露 | 直接读取响应 | 2 层 | L792-793 (mask_phone/email) |
| **资金溯源** | `/recharge` POST | 异常资金流动 | 无日志难溯源 | 1 层 | L851 (log_balance_change) |

---

## 四、修复前后对比

| 对比维度 | 修复前（v1.0） | 修复后（v5.0） |
|----------|---------------|---------------|
| **身份获取方式** | 从 URL/表单接收 user_id | 从 session 读取当前用户名 |
| **水平越权** | 可修改 user_id 查看任何人 | 仅查看当前登录用户 |
| **充值对象** | user_id 参数可篡改为他人 | 自动充值当前登录用户 |
| **amount 格式** | 无校验 | 正则 `^\d+(\.\d{1,2})?$` |
| **负数充值** | 允许 -50000 | 拦截（amount <= 0） |
| **金额上限** | 无限制 | 单次 0.01 ~ 100000 |
| **批量Fuzz** | 无限制 | 每分钟最多 10 次 |
| **日志审计** | 无 | 每笔变动记录到 logs/balance.log |
| **敏感数据** | 明文显示手机/邮箱 | `138****8000` / `a***@example.com` |
| **IDOR探测过滤** | 无 | 5 类探测特征拦截 |
| **异常处理** | 可能抛 500 | try-except 中文提示 |

---

## 五、关键防御代码速查

### 5.1 /profile 路由（L768-800）

```python
@app.route("/profile")
def profile():
    cur_username = session.get("username")        # ① session 身份
    if not cur_username or cur_username not in USERS:
        return redirect("/login")

    row = c.execute("SELECT ... WHERE username = ?", (cur_username,)).fetchone()
    # ② 使用 username 查询，拒绝 user_id 参数

    user_data = {
        "email": mask_email(row[2]),              # ③ 邮箱脱敏
        "phone": mask_phone(row[3]),              # ④ 手机脱敏
    }
```

### 5.2 /recharge 路由（L809-855）

```python
@app.route("/recharge", methods=["POST"])
def recharge():
    cur_username = session.get("username")        # ① session 身份
    if not cur_username or cur_username not in USERS:
        return redirect("/login")

    if not check_rate_limit(client_ip, 10, 60):  # ② 限流
        return "充值过于频繁"

    filter_idor_probe(cur_username)               # ③ IDOR探测过滤

    if not re.match(r'^\d+(\.\d{1,2})?$', amount_str):  # ④ 格式
        return "金额格式错误"
    if amount <= 0:                                 # ⑤ 正负
        return "金额必须大于 0"
    if amount < RECHARGE_MIN:                       # ⑥ 下限
        return "最低充值 0.01 元"
    if amount > RECHARGE_MAX:                       # ⑦ 上限
        return "最高充值 100000 元"

    USERS[cur_username]["balance"] += amount       # ⑧ 充值
    log_balance_change(...)                         # ⑨ 审计日志
```
