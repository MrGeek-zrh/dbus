#ifndef SERVICE_STATS_H
#define SERVICE_STATS_H

#include "dbus/dbus-connection.h"

// 需要保存哪些状态呢？
// 每个连接专有的connection肯定要保存
typedef struct service_state {
    DBusConnection *connection;
} service_state;

static dbus_bool_t save_service_status(char *service_name, char *file_path, service_state *state);

#endif // SERVICE_STATS_H
