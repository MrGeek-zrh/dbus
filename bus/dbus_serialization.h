#ifndef DBUS_SERIALIZATION_H
#define DBUS_SERIALIZATION_H

#include <stdlib.h>
#include "dbus/dbus-connection.h"

#ifdef __cplusplus
extern "C" {
#endif

void *serialize_dbus_connection(const DBusConnection *connection, size_t *size);
DBusConnection *deserialize_dbus_connection(const void *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif // DBUS_SERIALIZATION_H
