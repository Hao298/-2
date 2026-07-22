# IDOR水平越权与业务逻辑漏洞实训报告

---

## 一、基础信息

| 项目 | 内容 |
|------|------|
| **实训项目** | IDOR水平越权与业务逻辑漏洞挖掘实战 |
| **实训学员** | 大二网络安全专业学生 |
| **实训日期** | 2026-07-22 |
| **实训环境** | Kali Linux 2026.2 / Python Flask + SQLite / Burp Suite |
| **靶机地址** | 192.168.126.133:5000 |
| **项目位置** | /opt/Class01/ |
| **项目背景** | 连续四天迭代的Flask用户管理系统 |
| **今日新增** | /profile个人中心、/recharge充值（原始代码无归属鉴权、无限流、无日志） |
| **核心文件** | app.py / templates/profile.html |
| **实训课程** | 第一场《Web安全渗透测试与靶场实战培训》、第二场《业务逻辑漏洞实战与渗透测试报告撰写培训》 |

---

## 二、实验目的

1. 理解水平越权（IDOR—Insecure Direct Object Reference）漏洞原理：服务端过度信任前端传入的ID参数
2. 掌握Burp Suite Intruder Sniper模式枚举user_id批量拖取用户信息的手法
3. 学习业务逻辑漏洞中"过度信任客户端参数"的攻击思路：前端限制可被Burp抓包篡改
4. 理解负数金额恶意扣款漏洞的本质：仅在前端做正负校验等于没做
5. 掌握Session作为服务端可信数据源的正确使用方式：身份从Session读取，拒绝前端传递
6. 串联四天学习脉络：SQL注入→WAF绕过→文件上传→越权与业务逻辑

---

## 三、今日实训三阶段工作概述

### 第一阶段：业务功能开发（09:00-10:00）

快速开发了/profile个人中心和/recharge充值两个业务模块，原始代码完全依赖前端传入的参数：

```python
# app.py v1.0 — /profile 原始代码（零校验）
@app.route("/profile")
def profile():
    user_id = request.args.get("user_id", "")       # ① 直接信任URL参数
    row = c.execute("SELECT ... WHERE id = ?", (user_id,)).fetchone()
    return render_template("profile.html", user=user_data)

# app.py v1.0 — /recharge 原始代码（零校验）
@app.route("/recharge", methods=["POST"])
def recharge():
    user_id = request.form.get("user_id", "")        # ② 直接信任表单参数
    amount = request.form.get("amount", "0")         # ③ 直接信任金额，不做任何校验
    USERS[username]["balance"] += float(amount)      # ④ 负数也可以加进去
```

关键问题：
- `/profile` 使用URL参数 `?user_id=N` 决定查询谁 → 可篡改
- `/recharge` 使用表单隐藏域 `user_id` 决定给谁充值 → 可篡改
- `amount` 不做任何正负校验 → 负数就是"反向转账"
- 无登录鉴权：未登录也能访问 → 匿名越权

### 第二阶段：Burp手工渗透测试（10:00-12:00）

使用本次培训两场会议学到的攻击手法进行测试。

**第一场培训知识点回顾：IDOR水平越权**
> 讲师演示：某系统修改URL中`id=123`为`id=124`即可查看他人订单详情，管理员无需登录即可遍历全部订单号。本节实训对标该案例。

**攻击验证1 — 水平越权查看他人资料：**
```http
GET /profile?user_id=2 HTTP/1.1
Host: 192.168.126.133:5000
Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0...
```
→ 返回alice的完整资料（手机号13900139001、余额100），越权成功！

**攻击验证2 — Burp Intruder Sniper模式批量枚举：**
使用Burp Intruder Sniper模式，设置Payload为数字1~1000：
```
GET /profile?user_id=§1§ HTTP/1.1    ← Payload标记点
```
→ 1000次请求仅需数秒，返回所有用户ID对应的资料，批量拖库完成。

**第二场培训知识点回顾：业务逻辑漏洞**
> 讲师演示：某商城修改购物车数量为负数实现"反向转账"；修改商品单价为0.01元实现"一分钱购物"。核心教训：前端所有限制均可通过Burp绕过。

**攻击验证3 — 负数金额恶意扣款：**
```http
POST /recharge HTTP/1.1
Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0...
Content-Type: application/x-www-form-urlencoded

user_id=1&amount=-50000
```
→ Balance从99999变为49999，分钟到账"反向扣款"成功。

**攻击验证4 — 枚举充值其他用户：**
```http
POST /recharge HTTP/1.1
Cookie: session=sess_a...
Content-Type: application/x-www-form-urlencoded

user_id=2&amount=500000
```
→ 当前登录用户admin，给`user_id=2`（alice）充值500000成功，IDOR越权充值。

全部攻击验证通过后，确认该接口存在越权+负数金额两类高危漏洞。

### 第三阶段：分层漏洞加固 + 全用例回归复测（14:00-17:00）

| 轮次 | 改造重点 | 新增防御 |
|------|----------|----------|
| **第1轮** | Session身份加固 | profile和recharge均从session获取当前用户，删除user_id参数信任 |
| **第2轮** | amount校验 | 正则格式+正负检查+金额上下限（0.01~100000） |
| **第3轮** | 限流+日志+脱敏 | check_rate_limit / log_balance_change / mask_phone/email |
| **第4轮** | IDOR探测过滤 | filter_idor_probe() 拦截批量探测特征 |

每轮改造后用第一阶段的全部Payload重新测试，确认旧攻击方式不再生效。

---

## 四、漏洞汇总表格

| 编号 | 漏洞类型 | 风险等级 | 攻击入口 | 修复状态 |
|------|----------|----------|----------|----------|
| VUL-I01 | 水平越权IDOR — 查看他人资料 | **高危** | `/profile?user_id=N` | ✅ 已修复 |
| VUL-I02 | 水平越权IDOR — 篡改他人余额 | **高危** | `/recharge` 表单user_id | ✅ 已修复 |
| VUL-I03 | 负数金额恶意扣款 | **高危** | `/recharge` 表单amount | ✅ 已修复 |
| VUL-I04 | 超小额刮削（0.001元） | **中危** | `/recharge` 表单amount | ✅ 已修复 |
| VUL-I05 | 超巨额充值突破系统限制 | **中危** | `/recharge` 表单amount | ✅ 已修复 |
| VUL-I06 | 批量枚举拖库（Burp Intruder） | **高危** | `/profile?user_id=1~1000` | ✅ 已修复 |
| VUL-I07 | 敏感信息泄露（手机号、邮箱明文） | **中危** | `/profile` 响应 | ✅ 已修复 |
| VUL-I08 | 畸形amount载荷绕过 | **中危** | `/recharge` 表单amount | ✅ 已修复 |
| VUL-I09 | 未授权访问/profile | **中危** | 直接访问 /profile | ✅ 已修复 |
| VUL-I10 | 异常资金行为不可追溯 | **低危** | 充值无日志 | ✅ 已修复 |

---

## 五、分项漏洞原理 + POC复现 + 分层修复代码方案

### 5.1 VUL-I01 / VUL-I06 水平越权查看他人资料 + 批量枚举

#### 漏洞原理

对应第一场培训讲师演示案例：**"修改URL中的ID参数即可查看他人订单"**。

原始代码直接信任URL参数中的user_id，未验证该user_id是否属于当前登录用户：

```python
# 原始高危代码
user_id = request.args.get("user_id", "")        # ① 用户可控
row = c.execute("SELECT ... FROM users WHERE id = ?", (user_id,)).fetchone()
# ② 直接用user_id查数据库，不检查归属
```

攻击者登录后只需将URL从 `/profile?user_id=1` 改为 `?user_id=2` 即可查看alice的全部资料。

#### POC复现

**Burp数据包：**
```http
GET /profile?user_id=2 HTTP/1.1
Host: 192.168.126.133:5000
Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0...
```

**Burp Intruder Sniper配置：**
```
Payload type: Numbers
Range: 1-1000
Step: 1
```
→ 1000个请求自动发送，返回所有用户资料。

**curl批量枚举脚本：**
```bash
for i in {1..100}; do
  curl -b cookies.txt "http://192.168.126.133:5000/profile?user_id=$i"
done
```

#### 分层修复方案

| 层级 | 修复措施 | 代码位置 | 行号 |
|------|----------|----------|------|
| **底层根治** | 身份从session读取，拒绝前端传参 | `cur_username = session.get("username")` | L772 |
| **底层根治** | SQL查询改用username，不再使用user_id | `SELECT ... WHERE username = ?` | L779 |
| **辅助-脱敏** | 手机号、邮箱脱敏显示 | `mask_phone()` / `mask_email()` | L792-793 |
| **辅助-限流** | 每分钟最多10次请求 | `check_rate_limit(ip, 10, 60)` | L817-821 |
| **辅助-过滤** | IDOR探测特征过滤 | `filter_idor_probe()` | L824-826 |

```python
# 修复后（v5.0）
@app.route("/profile")
def profile():
    cur_username = session.get("username")         # ① session身份（不可伪造）
    if not cur_username:                           # ② 未登录跳转
        return redirect("/login")

    row = c.execute(                               # ③ 用username查询
        "SELECT ... FROM users WHERE username = ?",
        (cur_username,)
    ).fetchone()

    return render_template("profile.html", user={
        "email": mask_email(row[2]),               # ④ 脱敏输出
        "phone": mask_phone(row[3]),
    })
```

---

### 5.2 VUL-I02 / VUL-I03 负数金额恶意扣款 + 越权充值

#### 漏洞原理

对应第二场培训讲师演示案例：**"修改购物车商品数量为负数实现反向转账"**。

原始代码存在两个独立漏洞：

```python
# 原始高危代码
user_id = request.form.get("user_id", "")     # ① 信任表单隐藏域中的user_id
amount = request.form.get("amount", "0")      # ② 信任amount，不做正负检查
USERS[username]["balance"] += float(amount)    # ③ 负数直接参与加法运算
```

攻击者可以通过：
1. 修改隐藏域 `user_id` → 给他人充值（无权限检查）
2. 传 `amount=-50000` → 从自己余额扣款（相当于盗取平台资金）
3. 传 `amount=0.001` → 超小额反复充值（刮削攻击）

#### POC复现

**Burp数据包（负数金额 + 越权充值）：**
```http
POST /recharge HTTP/1.1
Host: 192.168.126.133:5000
Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0...
Content-Type: application/x-www-form-urlencoded

user_id=2&amount=-50000
```
→ 给user_id=2（alice）充-50000，alice余额被扣减。

**curl命令：**
```bash
# 给自己充负值（反向扣款）
curl -b cookies.txt -X POST \
  -d "user_id=1&amount=-50000" \
  "http://192.168.126.133:5000/recharge"

# 超小额刮削
curl -b cookies.txt -X POST \
  -d "user_id=1&amount=0.001" \
  "http://192.168.126.133:5000/recharge"

# 畸形载荷
curl -b cookies.txt -X POST \
  -d "user_id=1&amount=1e5" \
  "http://192.168.126.133:5000/recharge"
```

#### 分层修复方案

| 层级 | 防御措施 | 代码 | 行号 |
|------|----------|------|------|
| **底层-身份固化** | session读取，拒绝前端user_id | `cur_username = session.get(...)` | L813 |
| **底层-格式校验** | 正则 `^\d+(\.\d{1,2})?$` | `re.match(...)` | L834 |
| **底层-正负校验** | `if amount <= 0: return error` | 拦截负数、0 | L838-840 |
| **底层-下限拦截** | `RECHARGE_MIN = 0.01` | 拦截超小额 | L842-843 |
| **底层-上限拦截** | `RECHARGE_MAX = 100000` | 拦截超巨额 | L844-845 |
| **辅助-限流** | 每分钟最多10次 | `check_rate_limit(ip, 10, 60)` | L817-821 |
| **辅助-日志** | 每笔变动记录 | `log_balance_change(...)` | L851 |

```python
# 修复后充值校验流水线（v5.0）
amount_str = request.form.get("amount", "").strip()
if not amount_str:                                    # 非空
    return "金额不能为空"
if not re.match(r'^\d+(\.\d{1,2})?$', amount_str):   # 格式
    return "金额格式错误"
amount = float(amount_str)
if amount <= 0:                                       # 正负
    return "金额必须大于 0"
if amount < RECHARGE_MIN:                             # 下限
    return "最低充值 0.01 元"
if amount > RECHARGE_MAX:                             # 上限
    return "最高充值 100000 元"
# 全部通过 → 执行充值
USERS[cur_username]["balance"] += amount
log_balance_change(cur_username, client_ip, amount, USERS[cur_username]["balance"])
```

---

### 5.3 VUL-I07 敏感信息泄露

#### 漏洞原理

原始代码将完整手机号和邮箱直接传递给前端模板渲染，即使只有查看自己资料的权限，攻击者也可通过浏览器开发者工具或爬虫批量收集用户个人信息。

#### 修复方案

```python
# 使用已有脱敏函数
user_data = {
    "email": mask_email(row[2]),   # admin@example.com → a***@example.com
    "phone": mask_phone(row[3]),   # 13800138000 → 138****8000
}
```

---

### 5.4 VUL-I10 无日志审计 + VUL-I09 未授权访问

| 漏洞 | 修复方案 | 代码 |
|------|----------|------|
| 未授权访问 | session登录检查 | `if not cur_username: return redirect("/login")` |
| 无日志审计 | 余额变动记录到 logs/balance.log | `log_balance_change(username, ip, amount, balance)` |

**日志格式示例：**
```
[2026-07-22 04:15:22] USER=admin  IP=127.0.0.1  AMOUNT=+200.00  BALANCE=100199.00
[2026-07-22 04:15:22] USER=admin  IP=127.0.0.1  AMOUNT=+300.00  BALANCE=100499.00
```

---

## 六、实训踩坑故障记录

### 坑1：cp命令覆盖文件时错位到/root根目录

**现象：** 用 `cp /opt/Class01/templates/profile.html /root/` 复制文件，结果出现在 `/root/profile.html` 而不是 `/root/templates/profile.html`，Git提交后发现多了根目录文件。

**解决：** `git rm --cached` 删除错误路径，`cp` 到正确位置后重新提交。后续使用 `cp /opt/Class01/templates/*.html /root/templates/` 批量操作。

### 坑2：balance += float(amount) 浮点数精度

**现象：** 多次充值后余额出现 0.0000001 级别的浮点数误差，导致页面显示 `¥100000.0000001`。

**解决：** 生产环境应使用 decimal.Decimal 或整数分存储。课堂环境暂用 `round(amount, 2)` 处理。

### 坑3：回测时越权仍然可访问

**现象：** 修复后测试 `/profile?user_id=2` 发现仍然返回 alice 的数据。检查代码发现忘记重启Flask服务，旧代码仍在运行。

**解决：** `fuser -k 5000/tcp` 强制杀掉进程后重启。养成修改代码后自动重启检查的习惯。

### 坑4：限流计数器不重置影响后续测试

**现象：** 测试限流功能发送了11次请求后看到限流提示。继续测试其他功能时发现所有请求都被限流拦截。

**解决：** 分组测试之间清空限流器 `_rate_store.clear()`，或者在测试脚本中重新 `test_client()`。

### 坑5：双后缀文件误拷贝到上传目录

**现象：** `cp /opt/Class01/templates/*` 复制时把 `.py` 和 `.html` 文件误拷贝到了 `static/uploads/` 目录，导致Git跟踪了这些文件。

**解决：** `.gitignore` 添加 `static/uploads/*` 规则，并用 `git rm --cached` 删除已跟踪文件。

---

## 七、加固前后安全对比表格

| 对比维度 | 修复前（v1.0） | 修复后（v5.0） |
|----------|---------------|---------------|
| **身份获取方式** | 从URL/表单接收user_id | 从session读取当前用户名 |
| **水平越权** | 修改?user_id=N可查看任何人 | 仅查看当前登录用户 |
| **充值对象** | 表单隐藏域user_id可篡改 | 自动充值当前登录用户 |
| **amount格式** | 无校验 | 正则 `^\d+(\.\d{1,2})?$` |
| **负数充值** | 允许 -50000 | 拦截（amount <= 0） |
| **金额上下限** | 无限制 | 单次 0.01 ~ 100000 |
| **批量Fuzz** | Burp Intruder无限制 | 每分钟最多10次 |
| **日志审计** | 无 | 每笔记录到 logs/balance.log |
| **敏感数据** | 明文显示手机/邮箱 | 138****8000 / a***@example.com |
| **IDOR探测过滤** | 无 | 5类探测特征拦截 |
| **异常处理** | 可能抛500 | try-except中文提示 |
| **认证检查** | 未登录也可访问 | session校验，未登录跳转 |
| **用户ID前端暴露** | 表单含user_id隐藏域 | 表单无user_id字段 |

---

## 八、复测用例

### 8.1 水平越权

| 编号 | 操作 | 预期结果 |
|------|------|----------|
| TC-I01 | 登录admin访问 `/profile` | 显示admin本人信息 |
| TC-I02 | 登录admin访问 `/profile?user_id=2` | 仍显示admin（参数被忽略） |
| TC-I03 | 登录alice访问 `/profile` | 显示alice本人信息 |
| TC-I04 | 未登录访问 `/profile` | 302跳转登录 |

### 8.2 金额校验

| 编号 | amount输入 | 预期结果 |
|------|-----------|----------|
| TC-I05 | `50` | 充值成功 |
| TC-I06 | `0.01` | 充值成功（下限边界） |
| TC-I07 | `100000` | 充值成功（上限边界） |
| TC-I08 | `-500` | 拦截：金额必须大于0 |
| TC-I09 | `0` | 拦截：金额必须大于0 |
| TC-I10 | `0.001` | 拦截：最低充值0.01元 |
| TC-I11 | `100001` | 拦截：最高充值100000元 |
| TC-I12 | `abc` | 拦截：金额格式错误 |
| TC-I13 | `1.234` | 拦截：金额格式错误 |
| TC-I14 | `1e5` | 拦截：金额格式错误 |
| TC-I15 | `1\n00` | 拦截：金额格式错误 |
| TC-I16 | `--100` | 拦截：金额格式错误 |
| TC-I17 | `0x10` | 拦截：金额格式错误 |

### 8.3 限流 + 日志

| 编号 | 操作 | 预期结果 |
|------|------|----------|
| TC-I18 | 同一IP连续充值10次 | 前10次成功 |
| TC-I19 | 第11次充值 | 拦截：充值过于频繁 |
| TC-I20 | 检查 logs/balance.log | 包含时间+用户+IP+金额+余额 |

### 8.4 脱敏

| 编号 | 操作 | 预期结果 |
|------|------|----------|
| TC-I21 | admin查看个人中心 | 邮箱显 a***@example.com |
| TC-I22 | admin查看个人中心 | 手机显 138****8000 |

### 8.5 原有功能不变

| 编号 | 操作 | 预期结果 |
|------|------|----------|
| TC-I23 | 注册新用户 | 302跳转登录页 |
| TC-I24 | admin登录 | 欢迎回来 |
| TC-I25 | 搜索alice | 结果表格含脱敏数据 |
| TC-I26 | 上传真实PNG | UUID命名+预览 |
| TC-I27 | 找回密码 | 手机验证+重置成功 |

---

## 九、实验总结与心得体会

### 9.1 四天实训的完整脉络

今天（Day4）是连续实训的最后一天，四天学到的内容恰好覆盖了Web漏洞中最主流的四类：

| 天数 | 主题 | 核心攻击手法 | 核心防御原则 |
|------|------|-------------|-------------|
| Day1 | SQL注入 | ' UNION SELECT，7步手工注入 | 参数化查询 |
| Day2 | WAF绕过 | 换行/注释/双层编码变形 | 纵深防御 |
| Day3 | 文件上传 | 路径穿越/图片马/双后缀 | 白名单+魔数 |
| Day4 | 越权+业务逻辑 | IDOR参数篡改/负数金额 | 绝不信任前端 |

今天的课让我感受最深的是：**前面三天的漏洞还需要一些技术水平去构造Payload，今天的越权完全是"改个数字就能搞定"**。讲师在第一场培训中演示的案例也是这样，把URL里的id从123改成124就看到了别人的订单。Burp Intruder一发出去，几千条数据几秒钟到手——没有任何技术含量，纯靠服务端"太懒"没做校验。

### 9.2 "前端校验等于没做"——第二场培训的核心教训

第二场培训讲师的一句话我记下来了：**"前端校验的唯一作用是减少正常用户的误操作，对于攻击者来说等于没有"**。

这次实训完全验证了这一点。原始代码的充值表单在前端写了一个 `min="0"` 的HTML属性，看起来好像限制了负数。但用Burp抓包后：

```
原始请求：amount=50
修改请求：amount=-50000
点击Forward → 服务器照单全收 → 余额从99999变成49999
```

整个绕过过程不到3秒。前端写的任何限制——`min`、`max`、`step`、`required`、`disabled`、`hidden`——在Burp面前都是透明的。**所有业务数值的校验必须在服务端完整做一遍**，这是今天最大的收获。

### 9.3 Session vs 前端参数的信任博弈

第二场培训讲师还讲了一个关键原则：**"Session是服务端可信数据源，表单/URL参数是前端不可控数据源，两者不可混用"**。

这次项目的代码就是典型的反面教材：

```
❌ 修复前：session存了你是谁（可信），但又从URL取user_id（不可信）
❌ 修复前：充值表单隐藏域 user_id（任何人都可以改）
✅ 修复后：一切身份相关信息只从session读
✅ 修复后：前端删除所有user_id的传参逻辑
```

这个设计原则不只是针对越权，SQL注入的参数化查询也是同一道理——**不要信任任何从客户端来的数据**。

### 9.4 越权与文件上传的危害对比

三天的文件上传防御用上了12步流水线，但越权漏洞的修复只需要核心一行代码——`cur_username = session.get("username")`。行数越少，说明这个问题越"基础"，但危害完全不比文件上传小。

| 漏洞 | 利用复杂度 | 危害范围 |
|------|-----------|----------|
| 文件上传 | 需要构造恶意文件 | 单点getshell |
| 水平越权 | 改一个数字 | 全部用户数据拖库 |
| 负数金额 | Burp改一个字段 | 无限套利/盗取资金 |

越权不需要发一个包就能全量拖走用户隐私数据，File upload至少还需要写个图片马。所以越权虽然"简单"，但在生产环境中的危害不容忽视。

### 9.5 纵深防御在越权场景中的应用

前三天学到的纵深防御思想今天同样适用。IDOR的防御不能只有一个session校验：

| 层级 | 防御 | 绕过可能性 |
|------|------|-----------|
| ① | session身份（底层） | Session固定攻击 |
| ② | 脱敏输出 | 脱敏后信息有限 |
| ③ | 限流 | IP代理池绕过 |
| ④ | IDOR探测过滤 | 变相互认绕过 |
| ⑤ | 审计日志 | 事后溯源 |

任何单层都可能被绕过，但多层叠加后攻击成本大幅增加。

---

## 十、生产环境拓展优化建议

### 10.1 权限模型引入RBAC

```python
# 当前：只有一种用户类型（admin/user）
# 生产：引入角色-权限模型
class Permission:
    VIEW_PROFILE = 1
    RECHARGE = 2
    MANAGE_USERS = 4

ROLE_PERMISSIONS = {
    "user":     Permission.VIEW_PROFILE | Permission.RECHARGE,
    "admin":    Permission.VIEW_PROFILE | Permission.RECHARGE | Permission.MANAGE_USERS,
    "auditor":  Permission.VIEW_PROFILE,
}
```

### 10.2 OWASP ASVS访问控制标准

```python
# OWASP ASVS V4 访问控制验证
def assert_ownership(resource_owner, current_user):
    if resource_owner != current_user:
        log_access_violation(current_user, resource_owner)
        raise PermissionError("无权访问该资源")
```

### 10.3 金额字段使用Decimal

```python
from decimal import Decimal

# 生产环境：整数分存储，避免浮点精度
amount_cents = int(Decimal(amount_str) * 100)   # 50.00元 → 5000分
```

### 10.4 Redis分布式限流

```python
import redis
r = redis.Redis()
key = f"recharge_rate:{request.remote_addr}"
if r.incr(key) > 10:
    return "限流"
r.expire(key, 60)
```

### 10.5 敏感操作二次验证

```python
# 充值/修改密码等敏感操作增加确认环节
@app.route("/recharge_confirm", methods=["POST"])
def recharge_confirm():
    # 发送短信验证码或邮箱确认码
    code = generate_code()
    send_sms(USERS[cur_username]["phone"], f"您的充值验证码：{code}")
    session["recharge_code"] = code
    return render_template("recharge_confirm.html")
```

### 10.6 安全配置汇总

```python
app.config['SESSION_COOKIE_HTTPONLY'] = True     # 禁止JS读取session
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'    # CSRF防护
app.config['SESSION_COOKIE_SECURE'] = True        # HTTPS Only
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
```

---

## 附录：个人中心与充值接口防御流水线（8步）

```
用户请求 /profile 或 /recharge
  ↓
  ① Session身份检查 (cur_username = session.get)
  ↓
  ② 拒绝URL/表单user_id参数（仅用session查询）
  ↓
  ③ SQL参数化查询（? 占位符，仅查当前用户）
  ↓
  ④ amount正则校验（^\d+(\.\d{1,2})?$）
  ↓
  ⑤ amount正负+上下限检查（>0, >=0.01, <=100000）
  ↓
  ⑥ IP限流（每分钟最多10次）
  ↓
  ⑦ 敏感数据脱敏输出（mask_phone/mask_email）
  ↓
  ⑧ 审计日志记录（logs/balance.log）
```

*报告人：大二网络安全实训生*
*日期：2026年7月22日*
