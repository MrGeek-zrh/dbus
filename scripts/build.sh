#! /usr/bin/env bash
set -e

# 获取脚本的绝对路径
SCRIPT_PATH=$(readlink -f "$0")
# 获取脚本所在的目录
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
# 切换到脚本所在的目录
cd "$SCRIPT_DIR" || exit
cd ..

mkdir -p build
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

sudo cat << EOF | sudo tee /lib/systemd/system/dbus.socket
[Unit]
Description=D-Bus System Message Bus Socket
# Do not stop on shutdown
DefaultDependencies=no
Wants=sysinit.target
After=sysinit.target

[Socket]
ListenStream=/run/dbus/system_bus_socket
EOF

sudo cat << EOF | sudo tee /lib/systemd/system/dbus.service 
[Unit]
Description=D-Bus System Message Bus
Documentation=man:dbus-daemon(1)
Requires=dbus.socket
# Do not stop on shutdown
DefaultDependencies=no
Wants=sysinit.target
After=sysinit.target basic.target

[Service]
ExecStart=@/usr/bin/dbus-daemon @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
ExecReload=/usr/bin/dbus-send --print-reply --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig
OOMScoreAdjust=-900
EOF