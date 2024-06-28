#!/usr/bin/env bash
set -e

# 定义颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # 无颜色

# 尝试重启 dbus 服务 
sudo systemctl daemon-reload
if sudo systemctl restart dbus; then
    echo -e "${GREEN}dbus 重启成功${NC}"
else
    echo -e "${RED}dbus 重启失败${NC}" >&2
    exit 1
fi