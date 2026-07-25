#!/bin/bash
# 先杀掉旧进程
pkill -9 npc 2>/dev/null
sleep 1
# 启动 npc 客户端连接 8024 端口
npc -server=us.ctfstu.com:8024 -vkey=264upkhqv8ggb6c2 -log=stdout -log_level=0 &
echo "npc 已启动，PID: $!"
# 保存 PID
echo $! > /tmp/npc.pid
