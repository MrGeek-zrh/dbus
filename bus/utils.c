/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* utils.c  General utility functions
 *
 * Copyright (C) 2003  CodeFactory AB
 * Copyright (C) 2003  Red Hat, Inc.
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <config.h>
#include "utils.h"
#include <dbus/dbus-sysdeps.h>
#include <dbus/dbus-mainloop.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <unistd.h>

const char bus_no_memory_message[] = "Memory allocation failure in message bus";

void
bus_connection_dispatch_all_messages (DBusConnection *connection)
{
  while (bus_connection_dispatch_one_message (connection))
    ;
}

dbus_bool_t
bus_connection_dispatch_one_message  (DBusConnection *connection)
{
  DBusDispatchStatus status;

  while ((status = dbus_connection_dispatch (connection)) == DBUS_DISPATCH_NEED_MEMORY)
    _dbus_wait_for_memory ();

  return status == DBUS_DISPATCH_DATA_REMAINS;
}

char *on_path(char *cmd, const char *rootfs)
{
    char *path = NULL;
    char *entry = NULL;
    char *saveptr = NULL;
    char cmdpath[PATH_MAX];
    int ret;

    path = getenv("PATH");
    if (!path)
        return NULL;

    path = strdup(path);
    if (!path)
        return NULL;

    entry = strtok_r(path, ":", &saveptr);
    while (entry) {
        if (rootfs)
            ret = snprintf(cmdpath, PATH_MAX, "%s/%s/%s", rootfs, entry, cmd);
        else
            ret = snprintf(cmdpath, PATH_MAX, "%s/%s", entry, cmd);

        if (ret < 0 || ret >= PATH_MAX)
            goto next_loop;

        if (access(cmdpath, X_OK) == 0) {
            free(path);
            return strdup(cmdpath);
        }

    next_loop:
        entry = strtok_r(NULL, ":", &saveptr);
    }

    free(path);
    return NULL;
}
