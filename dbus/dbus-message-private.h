/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-message-private.h header shared between dbus-message.c and dbus-message-util.c
 *
 * Copyright (C) 2005  Red Hat Inc.
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
#ifndef DBUS_MESSAGE_PRIVATE_H
#define DBUS_MESSAGE_PRIVATE_H

#include <dbus/dbus-message.h>
#include <dbus/dbus-message-internal.h>
#include <dbus/dbus-string.h>
#include <dbus/dbus-dataslot.h>
#include <dbus/dbus-marshal-header.h>

DBUS_BEGIN_DECLS

/**
 * @addtogroup DBusMessageInternals
 * @{
 */

/**
 * @typedef DBusMessageLoader
 *
 * The DBusMessageLoader object encapsulates the process of converting
 * a byte stream into a series of DBusMessage. It buffers the incoming
 * bytes as efficiently as possible, and generates a queue of
 * messages. DBusMessageLoader is typically used as part of a
 * DBusTransport implementation. The DBusTransport then hands off
 * the loaded messages to a DBusConnection, making the messages
 * visible to the application.
 *
 * @todo write tests for break-loader that a) randomly delete header
 * fields and b) set string fields to zero-length and other funky
 * values.
 *
 */

/**
 * Implementation details of DBusMessageLoader.
 * All members are private.
 */
struct DBusMessageLoader {
    int refcount; /**< Reference count. */
    // 引用计数，用于跟踪该对象的引用次数。

    DBusString data; /**< Buffered data */
    // 缓冲的数据，用于存储尚未完全处理的原始数据。

    DBusList *messages; /**< Complete messages. */
    // 存储已完整接收并解析的消息列表。

    long max_message_size; /**< Maximum size of a message */
    // 消息的最大大小，用于防止恶意消息导致内存消耗过大。

    long max_message_unix_fds; /**< Maximum unix fds in a message */
    // 消息中最大 Unix 文件描述符的数量。

    DBusValidity corruption_reason; /**< why we were corrupted */
    // 数据损坏的原因，指示为什么数据被认为是损坏的。

    unsigned int corrupted : 1; /**< We got broken data, and are no longer working */
    // 表示是否接收到损坏的数据，如果为1，表示数据损坏，加载器不再工作。

    unsigned int buffer_outstanding : 1; /**< Someone is using the buffer to read */
    // 表示是否有进程正在使用缓冲区进行读取。

#ifdef HAVE_UNIX_FD_PASSING
    unsigned int unix_fds_outstanding : 1; /**< Someone is using the unix fd array to read */
    // 表示是否有进程正在使用 Unix 文件描述符数组进行读取。

    int *unix_fds; /**< File descriptors that have been read from the transport but not yet been handed to any message. Array will be allocated at first use. */
    // 从传输中读取但尚未交给任何消息的文件描述符。数组将在首次使用时分配。

    unsigned n_unix_fds_allocated; /**< Number of file descriptors this array has space for */
    // 该数组分配的文件描述符的数量。

    unsigned n_unix_fds; /**< Number of valid file descriptors in array */
    // 数组中有效文件描述符的数量。

    void (*unix_fds_change)(void *); /**< Notify when the pending fds change */
    // 当挂起的文件描述符发生变化时通知。

    void *unix_fds_change_data; /**< Data to be passed to the unix_fds_change callback function */
    // 传递给 unix_fds_change 回调函数的数据。
#endif
};

/** How many bits are in the changed_stamp used to validate iterators */
#define CHANGED_STAMP_BITS 21

/**
 * @brief Internals of DBusMessage
 *
 * Object representing a message received from or to be sent to
 * another application. This is an opaque object, all members
 * are private.
 */
struct DBusMessage {
    DBusAtomic refcount; /**< Reference count */
    // 引用计数器，用于跟踪该消息的引用数量。当引用计数器降到0时，消息将被销毁。

    DBusHeader header; /**< Header network data and associated cache */
    // 消息头部，包括网络数据和相关的缓存。消息头部包含消息类型、目标路径、接口、方法名称等信息。

    DBusString body; /**< Body network data. */
    // 消息体部分，包含实际的网络数据（消息的内容）。

    unsigned int locked : 1; /**< Message being sent, no modifications allowed. */
    // 指示消息是否被锁定。当消息正在发送时，不允许对其进行修改。

#ifndef DBUS_DISABLE_CHECKS
    unsigned int in_cache : 1; /**< Has been "freed" since it's in the cache (this is a debug feature) */
    // 调试特性，指示消息是否已经被缓存。这意味着消息已被“释放”但仍在缓存中。
#endif

    DBusList *counters; /**< 0-N DBusCounter used to track message size/unix fds. */
    // 用于跟踪消息大小和 Unix 文件描述符数量的计数器列表。

    long size_counter_delta; /**< Size we incremented the size counters by. */
    // 增加到大小计数器中的值。用于调整计数器的大小。

    dbus_uint32_t changed_stamp : CHANGED_STAMP_BITS; /**< Incremented when iterators are invalidated. */
    // 当迭代器失效时增加的值。用于跟踪消息变化的时间戳。

    DBusDataSlotList slot_list; /**< Data stored by allocated integer ID */
    // 用于存储通过分配的整数 ID 存储的数据槽列表。

#ifndef DBUS_DISABLE_CHECKS
    int generation; /**< _dbus_current_generation when message was created */
    // 调试特性，记录消息创建时的当前生成号。用于检查消息的创建时间。
#endif

#ifdef HAVE_UNIX_FD_PASSING
    int *unix_fds;
    /**< Unix file descriptors associated with this message. These are
     closed when the message is destroyed, hence make sure to dup()
     them when adding or removing them here. */
    // 与此消息关联的 Unix 文件描述符数组。当消息被销毁时，这些文件描述符将被关闭。
    // 因此，在添加或删除文件描述符时，必须对其进行复制（dup）。

    unsigned n_unix_fds; /**< Number of valid fds in the array */
    // 数组中有效的 Unix 文件描述符数量。

    unsigned n_unix_fds_allocated; /**< Allocated size of the array */
    // 数组的已分配大小。

    long unix_fd_counter_delta; /**< Size we incremented the unix fd counter by */
    // 增加到 Unix 文件描述符计数器中的值。用于调整文件描述符计数器的大小。
#endif
};

DBUS_PRIVATE_EXPORT
dbus_bool_t _dbus_message_iter_get_args_valist(DBusMessageIter *iter, DBusError *error, int first_arg_type,
                                               va_list var_args);

/** @} */

DBUS_END_DECLS

#endif /* DBUS_MESSAGE_H */
