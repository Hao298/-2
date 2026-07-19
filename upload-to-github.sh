#!/bin/bash
# =============================================================================
# 脚本名称：root-upload-to-github.sh
# 功能描述：遍历 /root 目录下所有文本类文件，打包压缩后上传至指定 GitHub 仓库
# 运行环境：Kali Linux / Linux (root 用户)
# 作    者：Auto-generated
# 版    本：v1.0
#
# ⚠️  重 要 安 全 声 明 ⚠️
# 本脚本会读取 /root 下所有文件（含 .ssh/.env 等敏感文件），
# 并将其上传至第三方 GitHub 仓库。
# 【仅限本地实验环境演示使用，严禁在生产服务器或公网服务器上执行！】
# 执行前请确认您完全理解每一行代码的含义。
# =============================================================================

set -euo pipefail  # 遇到错误即退出 / 未定义变量报错 / 管道错误也退出

# =============================================================================
# 用户配置区 —— 请在这里填入你的信息
# =============================================================================

# 【必填】你的 GitHub 用户名（用于 git 配置）
GITHUB_USER="Hao298"

# 【必填】你的 GitHub 仓库名称（如果不存在，请先在 GitHub 网页上创建）
GITHUB_REPO="flask-web-app"

# 【必填】你的 GitHub 个人访问令牌（Personal Access Token）
# 创建方式：GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens
# 所需权限：Contents: write
GITHUB_TOKEN=""

# 【必填】目标分支名称（默认为 main，如果仓库初始化后是 master 请改为 master）
GITHUB_BRANCH="main"

# 【可选】提交时显示的 commit 消息
COMMIT_MSG="Auto backup: /root directory - $(date '+%Y-%m-%d %H:%M:%S')"

# 【可选】打包后的压缩包临时存放路径
ARCHIVE_DIR="/tmp/root-backup"
ARCHIVE_NAME="root-backup-$(date '+%Y%m%d_%H%M%S').tar.gz"

# 【可选】最大单个文件体积（字节），超过此大小则跳过内容读取（默认 10MB）
MAX_FILE_SIZE=$((10 * 1024 * 1024))

# =============================================================================
# 日志工具函数
# =============================================================================

# 定义颜色变量，使输出更清晰
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # 恢复默认颜色

# 输出信息日志（绿色）
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }

# 输出警告日志（黄色）
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

# 输出错误日志（红色），并退出脚本
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# 输出步骤标题（蓝色）
step()  { echo -e "\n${BLUE}══════════════════════════════════════════════════${NC}"; echo -e "${BLUE}[STEP]${NC}  $*"; echo -e "${BLUE}══════════════════════════════════════════════════${NC}\n"; }

# =============================================================================
# 前置检查：验证用户配置是否完整
# =============================================================================

step "检查用户配置"

# 检查 GitHub Token 是否填写
if [ -z "$GITHUB_TOKEN" ]; then
    # 尝试从环境变量读取（更安全的方式）
    GITHUB_TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
fi
if [ -z "$GITHUB_TOKEN" ]; then
    error "GITHUB_TOKEN 未设置！\n请在脚本中填写 GITHUB_TOKEN，或通过环境变量 GH_TOKEN 传入。"
fi

# 检查仓库名是否填写
if [ -z "$GITHUB_REPO" ]; then
    error "GITHUB_REPO 未设置！请填写你要推送到的 GitHub 仓库名称。"
fi

info "用户名: ${GITHUB_USER}"
info "仓库名: ${GITHUB_REPO}"
info "分支:   ${GITHUB_BRANCH}"
info "Token:  ********${GITHUB_TOKEN: -4}"

# =============================================================================
# 前置检查：检查系统依赖（git、tar、gzip）
# =============================================================================

step "检查系统依赖"

# 检查 git 是否安装
if ! command -v git &>/dev/null; then
    error "git 未安装！请先执行：apt-get install -y git"
fi
info "git 已安装：$(git --version)"

# 检查 tar 是否安装
if ! command -v tar &>/dev/null; then
    error "tar 未安装！请先执行：apt-get install -y tar"
fi
info "tar 已安装"

# 检查 gzip 是否安装
if ! command -v gzip &>/dev/null; then
    error "gzip 未安装！请先执行：apt-get install -y gzip"
fi
info "gzip 已安装"

# =============================================================================
# 步骤一：创建临时工作目录，准备打包
# =============================================================================

step "步骤一：创建临时工作目录"

# 清空并重建临时目录
rm -rf "$ARCHIVE_DIR"
mkdir -p "$ARCHIVE_DIR"
info "临时目录已创建：${ARCHIVE_DIR}"

# =============================================================================
# 步骤二：递归遍历 /root 目录，收集文件列表并复制文本文件
# =============================================================================

step "步骤二：遍历 /root 目录并收集文本文件"

# 计数器
TOTAL_FILES=0
COPIED_FILES=0
SKIPPED_BINARY=0
SKIPPED_TOO_LARGE=0
SKIPPED_PERM_DENIED=0

# 临时文件：收集所有需要打包的文件路径（以 null 分隔，防止文件名含空格/换行）
FILE_LIST=$(mktemp)

# 需要跳过的文件/目录模式（白名单 + 黑名单 结合）
# 黑名单：这些目录/文件不打包
SKIP_PATTERNS=(
    # 系统虚拟文件系统
    "/root/.cache/"
    "/root/.npm/"
    "/root/.local/share/"
    "/root/.venv/"
    "/root/__pycache__/"
    "/root/.openclaw/"
    # 敏感安全文件（不含私钥的公开部分可保留，但这里为安全全部跳过）
    "/root/.ssh/id_rsa"          # SSH 私钥 —— 绝对不应上传
    "/root/.ssh/id_ecdsa"        # SSH 私钥
    "/root/.ssh/id_ed25519"      # SSH 私钥
    "/root/.ssh/authorized_keys" # 授权密钥列表
    # 已打包文件自身
    "${ARCHIVE_DIR}/"
    # 临时目录
    "/tmp/"
)

# 使用 find 命令递归遍历 /root 下所有文件（含隐藏文件）
# - type f     : 只处理普通文件
# - not -empty : 跳过空文件（0 字节）
info "正在扫描 /root 目录下的所有文件..."

# 利用 find 递归列出所有文件，然后逐个判断
# 使用 process substitution 避免子 shell 导致计数器无法累加
while IFS= read -r -d '' filepath; do

    TOTAL_FILES=$((TOTAL_FILES + 1))

    # ---- 黑名单过滤 ----
    skip_this=false
    for pattern in "${SKIP_PATTERNS[@]}"; do
        if [[ "$filepath" == "$pattern"* ]]; then
            skip_this=true
            break
        fi
    done
    if $skip_this; then
        continue
    fi

    # ---- 检查文件是否可读 ----
    if [ ! -r "$filepath" ]; then
        warn "权限不足，跳过：${filepath}"
        SKIPPED_PERM_DENIED=$((SKIPPED_PERM_DENIED + 1))
        continue
    fi

    # ---- 检查文件大小是否超出限制 ----
    filesize=$(stat --format="%s" "$filepath" 2>/dev/null || echo 0)
    if [ "$filesize" -gt "$MAX_FILE_SIZE" ]; then
        warn "文件过大（$(numfmt --to=iec $filesize)），跳过内容：${filepath}"
        SKIPPED_TOO_LARGE=$((SKIPPED_TOO_LARGE + 1))
        # 对于超大文件，我们仍记录路径但不读内容 —— 后续打包时 tar 会自动处理
        # 这里选择也跳过打包，避免压缩包超大
        continue
    fi

    # ---- 二进制文件检测 ----
    # 使用 file 命令检查 MIME 类型
    mime_type=$(file --mime-type -b "$filepath" 2>/dev/null || echo "unknown")

    # 判断是否为文本类文件
    case "$mime_type" in
        text/*|application/json|application/xml|application/yaml|application/x-yaml| \
        application/javascript|application/x-perl|application/x-python| \
        application/x-shellscript|application/x-httpd-php| \
        application/x-tcl|application/x-csh|application/x-ruby| \
        application/xml-dtd|application/x-sh|application/x-csh| \
        application/x-awk|application/x-lisp|application/sql| \
        application/x-httpd-php-source|application/x-python-code| \
        application/x-bzip2|application/gzip|application/x-xz| \
        message/rfc822|inode/x-empty)
            # 是文本类文件，复制到临时目录
            ;;
        *)
            # 非文本文件（图片、视频、二进制等），跳过
            SKIPPED_BINARY=$((SKIPPED_BINARY + 1))
            continue
            ;;
    esac

    # ---- 复制文本文件到临时目录 ----
    # 计算相对路径（去掉 /root/ 前缀）
    rel_path="${filepath#/root/}"
    dest_path="${ARCHIVE_DIR}/${rel_path}"
    dest_dir=$(dirname "$dest_path")

    mkdir -p "$dest_dir"
    if cp "$filepath" "$dest_path" 2>/dev/null; then
        COPIED_FILES=$((COPIED_FILES + 1))
    else
        warn "复制失败，跳过：${filepath}"
    fi

done < <(find /root -type f -not -empty -print0 2>/dev/null || true)

# 输出统计信息
info "扫描完成："
info "  ├─ 扫描文件总数：  ${TOTAL_FILES}"
info "  ├─ 已复制文本文件：${COPIED_FILES}"
info "  ├─ 跳过二进制文件：${SKIPPED_BINARY}"
info "  ├─ 跳过超大文件：  ${SKIPPED_TOO_LARGE}"
info "  └─ 权限不足跳过：  ${SKIPPED_PERM_DENIED}"

# 清理临时文件
rm -f "$FILE_LIST"

# =============================================================================
# 步骤三：打包压缩
# =============================================================================

step "步骤三：打包压缩文件"

ARCHIVE_PATH="/tmp/${ARCHIVE_NAME}"

# 进入临时目录的父目录，用相对路径打包，避免压缩包内包含绝对路径
cd /tmp

tar czf "$ARCHIVE_PATH" \
    --owner=0 --group=0 \
    --transform="s|^$(basename "$ARCHIVE_DIR")/||" \
    "$(basename "$ARCHIVE_DIR")" 2>&1 || error "打包失败！请检查磁盘空间。"

info "压缩包已生成：${ARCHIVE_PATH}"
info "压缩包大小：$(ls -lh "$ARCHIVE_PATH" | awk '{print $5}')"

# =============================================================================
# 步骤四：初始化临时 git 仓库并推送
# =============================================================================

step "步骤四：推送至 GitHub 仓库"

# 创建独立的 git 工作目录
GIT_DIR="/tmp/root-git-push"
rm -rf "$GIT_DIR"
mkdir -p "$GIT_DIR"

# 将压缩包复制到 git 目录
cp "$ARCHIVE_PATH" "${GIT_DIR}/"
cd "$GIT_DIR"

# 生成一个简要的文件清单（markdown 格式）作为额外的说明
cat > FILE_LIST.md << EOF
# /root 备份文件清单

> 备份时间：$(date '+%Y-%m-%d %H:%M:%S')
> 备份来源：$(hostname)
> 压缩包：${ARCHIVE_NAME}

## 统计信息

| 项目 | 数值 |
|------|------|
| 扫描文件总数 | ${TOTAL_FILES} |
| 已复制文本文件 | ${COPIED_FILES} |
| 跳过二进制文件 | ${SKIPPED_BINARY} |
| 跳过超大文件 | ${SKIPPED_TOO_LARGE} |
| 权限不足跳过 | ${SKIPPED_PERM_DENIED} |

## 目录结构

\`\`\`
$(ls -R "${ARCHIVE_DIR}" 2>/dev/null | head -200)
\`\`\`
EOF

info "文件清单已生成"

# 初始化 git 仓库
git init
info "git 仓库已初始化"

# 配置 git 用户信息（仅对本次仓库有效）
git config user.name "${GITHUB_USER}"
git config user.email "${GITHUB_USER}@users.noreply.github.com"
info "git 用户已配置：${GITHUB_USER} <${GITHUB_USER}@users.noreply.github.com>"

# 添加所有文件到暂存区
git add -A

# 检查是否有文件被添加
if git diff --cached --quiet; then
    error "没有文件需要提交！临时目录为空，请检查扫描结果。"
fi

# 提交
git commit -m "$COMMIT_MSG" 2>&1 || error "git commit 失败！"

info "文件已本地提交"

# ---- 远程仓库认证与推送 ----
# 使用 Personal Access Token 作为密码进行认证
# URL 格式：https://<token>@github.com/<user>/<repo>.git
REMOTE_URL="https://${GITHUB_USER}:${GITHUB_TOKEN}@github.com/${GITHUB_USER}/${GITHUB_REPO}.git"

info "正在连接远程仓库：${GITHUB_USER}/${GITHUB_REPO}"

# 添加远程仓库
git remote add origin "$REMOTE_URL"

# 尝试拉取远程分支（如果仓库已存在且有内容），确保能正常合并
info "检查远程仓库状态..."
if git ls-remote --exit-code origin "$GITHUB_BRANCH" &>/dev/null; then
    info "远程分支 ${GITHUB_BRANCH} 已存在，尝试拉取合并..."
    # 允许合并不相关的历史
    git pull origin "$GITHUB_BRANCH" --allow-unrelated-histories -X theirs 2>&1 || warn "远程拉取失败，将继续推送（可能是空仓库）。"
else
    info "远程分支 ${GITHUB_BRANCH} 尚不存在，将创建新分支。"
fi

# 推送至远程仓库
info "正在推送至 GitHub..."
if git push -u origin "HEAD:${GITHUB_BRANCH}" 2>&1; then
    echo ""
    echo -e "${GREEN}████████████████████████████████████████████████████████████████${NC}"
    echo -e "${GREEN}██                                                          ██${NC}"
    echo -e "${GREEN}██  🎉  上传成功！                                          ██${NC}"
    echo -e "${GREEN}██                                                          ██${NC}"
    echo -e "${GREEN}██  仓库地址：                                              ██${NC}"
    echo -e "${GREEN}██  https://github.com/${GITHUB_USER}/${GITHUB_REPO}         ██${NC}"
    echo -e "${GREEN}██                                                          ██${NC}"
    echo -e "${GREEN}██  分支：${GITHUB_BRANCH}                                         ██${NC}"
    echo -e "${GREEN}██                                                          ██${NC}"
    echo -e "${GREEN}████████████████████████████████████████████████████████████████${NC}"
    echo ""
else
    error "git push 失败！
    可能的原因：
    1. Token 无效或已过期 —— 请在 GitHub 重新生成
    2. Token 权限不足 —— 需要 Contents: write 权限
    3. 仓库不存在 —— 请先在 https://github.com/${GITHUB_USER} 创建仓库 ${GITHUB_REPO}
    4. 网络连接问题 —— 请检查能否访问 github.com
    "
fi

# =============================================================================
# 步骤五：清理临时文件
# =============================================================================

step "步骤五：清理临时文件"

rm -rf "$ARCHIVE_DIR"
rm -rf "$GIT_DIR"
# 保留压缩包在 /tmp 下，如需删除可取消下面注释
# rm -f "$ARCHIVE_PATH"

info "临时文件已清理（压缩包保留在 ${ARCHIVE_PATH}）"
info "脚本执行完毕！"

# =============================================================================
# 脚本结束
# =============================================================================
