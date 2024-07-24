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
/**
 * DBusTransportVTable 结构体定义了一组用于处理 DBusTransport 对象的函数指针。
 * 这些函数指针定义了与传输相关的操作，如初始化、读写、断开连接等。
 */
struct DBusTransportVTable {
    void (*finalize)(DBusTransport *transport);
    /**< finalize 方法必须释放 transport 对象的内存。
     *
     * @param transport 指向 DBusTransport 对象的指针
     */

    dbus_bool_t (*handle_watch)(DBusTransport *transport, DBusWatch *watch, unsigned int flags);
    /**< handle_watch 方法根据 flags 指示的读/写操作处理数据。
     *
     * @param transport 指向 DBusTransport 对象的指针
     * @param watch 指向 DBusWatch 对象的指针
     * @param flags 标志，指示读/写操作
     * @return 如果处理成功则返回 TRUE，否则返回 FALSE
     */

    void (*disconnect)(DBusTransport *transport);
    /**< disconnect 方法断开此传输。
     *
     * @param transport 指向 DBusTransport 对象的指针
     */

    dbus_bool_t (*connection_set)(DBusTransport *transport);
    /**< 当 transport->connection 已填充时调用。
     *
     * @param transport 指向 DBusTransport 对象的指针
     * @return 如果设置成功则返回 TRUE，否则返回 FALSE
     */

    void (*do_iteration)(DBusTransport *transport, unsigned int flags, int timeout_milliseconds);
    /**< 执行一次迭代（阻塞在 select/poll 上，然后读取或写入数据）。
     *
     * @param transport 指向 DBusTransport 对象的指针
     * @param flags 标志，指示操作类型
     * @param timeout_milliseconds 超时时间，单位为毫秒
     */

    void (*live_messages_changed)(DBusTransport *transport);
    /**< 未处理消息计数器发生变化时调用。
     *
     * @param transport 指向 DBusTransport 对象的指针
     */

    dbus_bool_t (*get_socket_fd)(DBusTransport *transport, DBusSocket *fd_p);
    /**< 获取套接字文件描述符。
     *
     * @param transport 指向 DBusTransport 对象的指针
     * @param fd_p 指向 DBusSocket 对象的指针
     * @return 如果获取成功则返回 TRUE，否则返回 FALSE
     */
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
