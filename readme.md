编译dbus
```shell
# 在项目根目录
mkdir build
cd build
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_C_FLAGS="-pg" -DCMAKE_CXX_FLAGS="-pg" ..
make -j$(nproc)
cp compile_commands.json ..
```
```
