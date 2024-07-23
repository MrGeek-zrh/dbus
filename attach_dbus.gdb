# attach_dbus.gdb

define attach_dbus
  shell echo "Attaching to dbus-daemon with PID:" 276037
  attach 276037
end

attach_dbus
