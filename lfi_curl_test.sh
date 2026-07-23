#!/bin/bash
# ==============================================================================
# /page LFI 路径遍历 + 文件包含 curl 批量测试脚本
# 靶机: http://192.168.126.133:5000
# 接口: /page?name=<payload>
# 依据: 《文件包含漏洞原理与实战利用培训》全部攻击载荷
# 预期: 修复前全部成功读取, 修复后全部拦截返回"页面不存在"
# 注意: 仅测试/page路由, 不干扰其他模块
# ==============================================================================

TARGET="http://192.168.126.133:5000"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

echo ""
echo "============================================================"
echo "  /page 接口 — LFI 路径遍历 + 文件包含 批量测试"
echo "  靶机: $TARGET"
echo "  测试用例数: 14"
echo "============================================================"
echo ""

# ================================================================
# 测试用例 1: 正常功能 — 白名单页面
# 课堂知识点: 业务正常请求, 验证功能可用性
# 修复前: 返回帮助中心内容
# 修复后: 返回帮助中心内容（不变）
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} 正常业务 — 白名单页面 help"
echo "  知识点: 文件包含业务正常调用"
RESP=$(curl -s "$TARGET/page?name=help")
if echo "$RESP" | grep -q "帮助中心"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 帮助中心内容正常返回"
    PASS=$((PASS+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 未显示帮助中心内容"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 测试用例 2: 陌生页面 — 白名单拦截
# 课堂知识点: 文件包含入口管控, 未授权页面禁止访问
# 修复前: 可能返回空或报错
# 修复后: 返回"页面不存在"
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} L1白名单 — 陌生页面 notexist"
echo "  知识点: L1 白名单管控, 非白名单名称直接拒绝"
RESP=$(curl -s "$TARGET/page?name=notexist")
if echo "$RESP" | grep -q "页面不存在"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 白名单拦截生效"
    PASS=$((PASS+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 应返回'页面不存在'"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 测试用例 3: 单级 ../ 穿越 — 读取 app.py
# 课堂知识点: 路径遍历基础, ../ 返回上级目录
# 修复前: pages/../app.py → 直接读取 app.py 源码
# 修复后: L1白名单 + L2路径锁定 双重拦截
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} 单级 ../ 穿越 — 读取 app.py"
echo "  知识点: 目录遍历基础, ../ 跳转至项目根目录"
RESP=$(curl -s "$TARGET/page?name=../app.py")
if echo "$RESP" | grep -q "页面不存在"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 页面不存在（拦截成功）"
    PASS=$((PASS+1))
elif echo "$RESP" | grep -q "Flask\|app.run\|secret_key"; then
    echo -e "  结果: ${RED}❌ FAIL${NC} — 源码泄露! 包含 app.py 内容"
    FAIL=$((FAIL+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 未知响应"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 测试用例 4: 多级 ../../../ 穿越 — 读取 /etc/passwd
# 课堂知识点: 多级深度遍历, ../../../ 逃逸至系统根目录
# 修复前: pages/../../../etc/passwd → 读取系统用户列表
# 修复后: L1+L2 拦截
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} 多级 ../../../ 穿越 — 读取 /etc/passwd"
echo "  知识点: 多级深度目录穿越, ../../.. 跳至系统根目录"
RESP=$(curl -s "$TARGET/page?name=../../../etc/passwd")
if echo "$RESP" | grep -q "页面不存在"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 页面不存在（拦截成功）"
    PASS=$((PASS+1))
elif echo "$RESP" | grep -q "root:\|nobody:\|daemon:"; then
    echo -e "  结果: ${RED}❌ FAIL${NC} — 系统密码文件泄露! 含 /etc/passwd 内容"
    FAIL=$((FAIL+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 未知响应"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 测试用例 5: 深度 ../../../../ 穿越 — 读取 /etc/shadow
# 课堂知识点: 更深度穿越探测, 尝试读取加密口令
# 修复前: 读取 /etc/shadow（权限允许时）
# 修复后: L1+L2 拦截
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} 深度 ../../../../ 穿越 — 读取 /etc/shadow"
echo "  知识点: 深度遍历 + 系统敏感文件探测"
RESP=$(curl -s "$TARGET/page?name=../../../../etc/shadow")
if echo "$RESP" | grep -q "页面不存在"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 页面不存在（拦截成功）"
    PASS=$((PASS+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 应返回'页面不存在'"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 测试用例 6: 读取 .env 配置文件
# 课堂知识点: 路径遍历获取密钥、Token等敏感配置
# 修复前: 读取项目 .env 文件泄露密钥
# 修复后: L1+L2 拦截
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} 穿越读取 .env 配置文件"
echo "  知识点: 路径遍历窃取环境变量、密钥"
RESP=$(curl -s "$TARGET/page?name=../.env")
if echo "$RESP" | grep -q "页面不存在"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 页面不存在（拦截成功）"
    PASS=$((PASS+1))
elif echo "$RESP" | grep -q "SECRET\|KEY\|TOKEN\|PASSWORD"; then
    echo -e "  结果: ${RED}❌ FAIL${NC} — 配置文件泄露! 含密钥信息"
    FAIL=$((FAIL+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 未知响应"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 测试用例 7: 读取 SQLite 数据库（二进制拖库）
# 课堂知识点: 大数据量文件读取, 用户隐私数据泄露
# 修复前: 拖取 users.db 获取全部用户数据
# 修复后: L1+L2 拦截
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} 穿越读取 SQLite 数据库 — 拖库"
echo "  知识点: 路径遍历拖取数据库, 全部用户数据泄露"
RESP=$(curl -s "$TARGET/page?name=../data/users.db")
if echo "$RESP" | grep -q "页面不存在"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 页面不存在（拦截成功）"
    PASS=$((PASS+1))
elif echo "$RESP" | grep -q "SQLite\|users\|admin"; then
    echo -e "  结果: ${RED}❌ FAIL${NC} — 数据库内容泄露! 可拖库"
    FAIL=$((FAIL+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 未知响应"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 测试用例 8: file:// 伪协议读取系统文件
# 课堂知识点: PHP类伪协议 file:// 直接读取系统文件
# 修复前: Python open()不支持, 但仍需做过滤
# 修复后: L3 伪协议特征拦截
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} file:// 伪协议 — 读取 /etc/passwd"
echo "  知识点: file:// 协议直接读取系统文件（PHP场景）"
RESP=$(curl -s "$TARGET/page?name=file:///etc/passwd")
if echo "$RESP" | grep -q "页面不存在"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 拦截成功"
    PASS=$((PASS+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 应返回'页面不存在'"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 测试用例 9: php://filter Base64 读取项目源码
# 课堂知识点: php://filter 流的 base64 编码读取源码, bypass 关键字检测
# 修复前: Python中不生效, 但L3应拦截伪协议特征
# 修复后: L3 伪协议特征拦截
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} php://filter Base64 编码读取 app.py"
echo "  知识点: php://filter 利用Base64编码读取PHP源码绕过检测"
RESP=$(curl -s --path-as-is "$TARGET/page?name=php://filter/convert.base64-encode/resource=app.py")
if echo "$RESP" | grep -q "页面不存在"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 拦截成功"
    PASS=$((PASS+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 应返回'页面不存在'"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 测试用例 10: data:// 伪协议注入
# 课堂知识点: data:// 协议直接在URL参数中嵌入任意数据, 实现代码注入
# 修复前: Python中不直接执行, 但L3应拦截
# 修复后: L3 伪协议特征拦截
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} data:// 伪协议 — 文本/代码直接注入"
echo "  知识点: data:// protocol 无需文件, 直接在参数中注入恶意载荷"
RESP=$(curl -s "$TARGET/page?name=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7")
if echo "$RESP" | grep -q "页面不存在"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 拦截成功"
    PASS=$((PASS+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 应返回'页面不存在'"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 测试用例 11: %00 空字节截断（Null Byte Injection）
# 课堂知识点: %00 截断, 利用C语言字符串以NULL结尾特性绕过后缀检查
# 修复前: help.html%00.txt → 实际读取 help.html
# 修复后: L3 %00 特征拦截
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} %00 空字节截断绕过"
echo "  知识点: Null Byte 截断, 利用C字符串NULL终止特性"
RESP=$(curl -s "$TARGET/page?name=help%00.txt")
if echo "$RESP" | grep -q "页面不存在"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 拦截成功"
    PASS=$((PASS+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 应返回'页面不存在'"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 测试用例 12: expect:// 伪协议 RCE
# 课堂知识点: expect:// 协议可执行系统命令, RCE风险
# 修复前: Python中不适用, 但L3应拦截
# 修复后: L3 伪协议特征拦截
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} expect:// 伪协议 RCE"
echo "  知识点: expect:// protocol 可执行系统命令, RCE高危"
RESP=$(curl -s "$TARGET/page?name=expect://id")
if echo "$RESP" | grep -q "页面不存在"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 拦截成功"
    PASS=$((PASS+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 应返回'页面不存在'"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 测试用例 13: 日志文件投毒 User-Agent SSI/RFI
# 课堂知识点: 在User-Agent中注入恶意代码写入日志, 通过LFI包含日志触发
# 修复前: 配合日志路径读取, 实现XSS或命令注入
# 修复后: L1+L2 拦截
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} 日志文件包含 — User-Agent 投毒"
echo "  知识点: 日志投毒RCE, User-Agent写入PHP代码→包含日志触发执行"
RESP=$(curl -s -A "<?php system('id');?>" "$TARGET/page?name=../../../var/log/apache2/access.log")
if echo "$RESP" | grep -q "页面不存在"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 拦截成功"
    PASS=$((PASS+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 应返回'页面不存在'"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 测试用例 14: HTML 注释泄露 — 读取模板文件
# 课堂知识点: 路径遍历读取前端模板, 获取调试注释中的敏感信息
# 修复前: 读取 login.html 获取硬编码管理员账号注释
# 修复后: L1+L2 拦截
# ================================================================
TOTAL=$((TOTAL+1))
echo -e "${YELLOW}[CASE $TOTAL]${NC} 路径遍历读取模板 — 调试信息泄露"
echo "  知识点: 模板源码泄露, 获取HTML注释中的调试账号密码"
RESP=$(curl -s "$TARGET/page?name=../templates/login.html")
if echo "$RESP" | grep -q "页面不存在"; then
    echo -e "  结果: ${GREEN}✅ PASS${NC} — 拦截成功"
    PASS=$((PASS+1))
elif echo "$RESP" | grep -q "调试信息\|默认管理员账号\|admin"; then
    echo -e "  结果: ${RED}❌ FAIL${NC} — 模板泄露! 含调试注释信息"
    FAIL=$((FAIL+1))
else
    echo -e "  结果: ${RED}❌ FAIL${NC} — 未知响应"
    FAIL=$((FAIL+1))
fi
echo ""

# ================================================================
# 汇总
# ================================================================
echo "============================================================"
echo -e "  测试完成: ${TOTAL} 用例 | ${GREEN}PASS: ${PASS}${NC} | ${RED}FAIL: ${FAIL}${NC}"
echo "============================================================"
echo ""
echo "修复判定标准:"
echo "  ✅ 全部14项 PASS = 文件包含漏洞修复通过"
echo "  ⚠️  CASE 1 必须 PASS (正常业务不受影响)"
echo "  ⚠️  CASE 3~14 全部拦截 = L1+L2+L3 三层防御全部生效"
echo "  ❌ 任一项 FAIL = 仍存在路径遍历/文件包含风险"
echo ""
echo "注意: 此脚本仅测试 /page 接口, 不影响原有 profile/recharge 复测用例"
echo ""
