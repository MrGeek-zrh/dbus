#! /usr/bin/env bash
set -e

# 获取脚本的绝对路径
SCRIPT_PATH=$(readlink -f "$0")
# 获取脚本所在的目录
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
# 切换到脚本所在的目录
cd "$SCRIPT_DIR" || exit

mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr \
	-DSYSCONF_INSTALL_DIR=/etc \
	-DLOCALSTATEDIR=/var \
	-DCMAKE_C_FLAGS="-pg -O0 -g" \
	-DCMAKE_CXX_FLAGS="-pg -O0 -g" \
	-DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
	-DDBUS_USE_SYSTEMD=ON
make -j$(nproc)
sudo make install
