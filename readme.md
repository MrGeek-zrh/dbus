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
