#!/usr/bin/env bash

# 定义绿色颜色
GREEN='\033[0;32m'
NC='\033[0m' # 无颜色

# 获取 dbus-daemon 的进程 ID 并用绿色包裹输出
PID=$(pgrep dbus-daemon)
if [ -n "$PID" ]; then
  echo -e "${GREEN}${PID}${NC}"
else
  echo "dbus-daemon 进程未找到"
fi