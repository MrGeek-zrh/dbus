#!/bin/bash
pid=$(pgrep dbus-daemon)
echo "Attaching to dbus-daemon with PID: $pid"

# 生成 GDB 命令文件
echo "define attach_dbus" >./dbus.gdb
echo "  attach $pid" >>./dbus.gdb
echo "end" >>./dbus.gdb
echo "attach_dbus" >>./dbus.gdb
