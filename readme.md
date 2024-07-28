编译dbus
```shell
# 在项目根目录
sudo apt install build-essential autoconf automake libtool pkg-config cmake libexpat1-dev
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
cp compile_commands.json ..
```

修改dbus.socket和dbus.service配置文件
```shell
sudo cat << EOF | tee /lib/systemd/system/dbus.socket
[Unit]
Description=D-Bus System Message Bus Socket
# Do not stop on shutdown
DefaultDependencies=no
Wants=sysinit.target
After=sysinit.target

[Socket]
ListenStream=/run/dbus/system_bus_socket
EOF
```

```shell
sudo cat << EOF | tee /lib/systemd/system/dbus.service
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
```

使用msgpack-c进行序列化
```shell
# 编译安装cJSON
git clone https://github.com/DaveGamble/cJSON.git
cd cJSON
mkdir build
cd build
cmake ..
make
sudo make install

# 编译安装msgpack-c
git clone https://github.com/msgpack/msgpack-c.git
cd msgpack-c
mkdir -p build
cd build
cmake ..
make
sudo make install
```

使用yajl进行json序列化
```shell
git clone https://github.com/lloyd/yajl.git
cd yajl
./configure
make
sudo make install
```
