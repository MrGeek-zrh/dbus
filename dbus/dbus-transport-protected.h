/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-transport-protected.h Used by subclasses of DBusTransport object (internal to D-Bus implementation)
 *
 * Copyright (C) 2002, 2004  Red Hat Inc.
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
#ifndef DBUS_TRANSPORT_PROTECTED_H
#define DBUS_TRANSPORT_PROTECTED_H

#include <dbus/dbus-internals.h>
#include <dbus/dbus-errors.h>
#include <dbus/dbus-transport.h>
#include <dbus/dbus-message-internal.h>
#include <dbus/dbus-auth.h>
#include <dbus/dbus-resources.h>

DBUS_BEGIN_DECLS

typedef struct DBusTransportVTable DBusTransportVTable;

/**
 * The virtual table that must be implemented to
 * create a new kind of transport.
 */
struct DBusTransportVTable {
    void (*finalize)(DBusTransport *transport);
    /**< The finalize method must free the transport. */

    dbus_bool_t (*handle_watch)(DBusTransport *transport, DBusWatch *watch, unsigned int flags);
    /**< The handle_watch method handles reading/writing
   * data as indicated by the flags.
   */

    void (*disconnect)(DBusTransport *transport);
    /**< Disconnect this transport. */

    dbus_bool_t (*connection_set)(DBusTransport *transport);
    /**< Called when transport->connection has been filled in */

    void (*do_iteration)(DBusTransport *transport, unsigned int flags, int timeout_milliseconds);
    /**< Called to do a single "iteration" (block on select/poll
   * followed by reading or writing data).
   */

    void (*live_messages_changed)(DBusTransport *transport);
    /**< Outstanding messages counter changed */

    dbus_bool_t (*get_socket_fd)(DBusTransport *transport, DBusSocket *fd_p);
    /**< Get socket file descriptor */
};

/**
 * Object representing a transport such as a socket.
 * A transport can shuttle messages from point A to point B,
 * and is the backend for a #DBusConnection.
 *
 */
struct DBusTransport {
    int refcount; /**< 引用计数，用于跟踪该对象的引用次数。 */

    const DBusTransportVTable *vtable; /**< 虚表，包含此实例的虚方法。 */

    DBusConnection *connection; /**< 拥有此传输的连接。 */

    DBusMessageLoader *loader; /**< 消息加载缓冲区，用于加载消息。 */

    DBusAuth *auth; /**< 认证会话，处理认证逻辑。 */

    DBusCredentials *credentials; /**< 从套接字读取的另一端的凭据。 */

    long max_live_messages_size; /**< 接收消息的最大总大小。 */
    long max_live_messages_unix_fds; /**< 接收消息的最大 Unix 文件描述符总数。 */

    DBusCounter *live_messages; /**< 所有活动消息的大小/Unix 文件描述符计数器。 */

    char *address; /**< 我们正在连接的服务器地址（对于服务器端的传输，该值为 NULL）。 */

    char *expected_guid; /**< 我们期望服务器具有的 GUID（服务器端或没有期望时为 NULL）。 */

    DBusAllowUnixUserFunction unix_user_function; /**< 检查用户是否被授权的函数。 */
    void *unix_user_data; /**< unix_user_function 的数据。 */

    DBusFreeFunction free_unix_user_data; /**< 用于释放 unix_user_data 的函数。 */

    DBusAllowWindowsUserFunction windows_user_function; /**< 检查用户是否被授权的函数（Windows）。 */
    void *windows_user_data; /**< windows_user_function 的数据。 */

    DBusFreeFunction free_windows_user_data; /**< 用于释放 windows_user_data 的函数。 */

    unsigned int disconnected : 1; /**< 如果我们已断开连接，则为 TRUE。 */
    unsigned int authenticated : 1; /**< 认证状态缓存；使用 _dbus_transport_peek_is_authenticated() 查询值。 */
    unsigned int send_credentials_pending : 1; /**< 如果需要发送凭据，则为 TRUE。 */
    unsigned int receive_credentials_pending : 1; /**< 如果需要接收凭据，则为 TRUE。 */
    unsigned int is_server : 1; /**< 如果在服务器端，则为 TRUE。 */
    unsigned int unused_bytes_recovered : 1; /**< 如果我们已从认证中恢复未使用的字节，则为 TRUE。 */
    unsigned int allow_anonymous : 1; /**< 如果允许匿名客户端连接，则为 TRUE。 */
};

dbus_bool_t _dbus_transport_init_base(DBusTransport *transport, const DBusTransportVTable *vtable,
                                      const DBusString *server_guid, const DBusString *address);
void _dbus_transport_finalize_base(DBusTransport *transport);

typedef enum {
    DBUS_TRANSPORT_OPEN_NOT_HANDLED, /**< we aren't in charge of this address type */
    DBUS_TRANSPORT_OPEN_OK, /**< we set up the listen */
    DBUS_TRANSPORT_OPEN_BAD_ADDRESS, /**< malformed address */
    DBUS_TRANSPORT_OPEN_DID_NOT_CONNECT /**< well-formed address but failed to set it up */
} DBusTransportOpenResult;

DBusTransportOpenResult _dbus_transport_open_platform_specific(DBusAddressEntry *entry, DBusTransport **transport_p,
                                                               DBusError *error);

#define DBUS_TRANSPORT_CAN_SEND_UNIX_FD(x) _dbus_auth_get_unix_fd_negotiated((x)->auth)

DBUS_END_DECLS

#endif /* DBUS_TRANSPORT_PROTECTED_H */
