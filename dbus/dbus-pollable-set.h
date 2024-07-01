/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/*
 * dbus-pollable-set.h - a set of pollable objects (file descriptors, sockets or handles)
 *
 * Copyright © 2011 Nokia Corporation
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301  USA
 *
 */

#ifndef DBUS_POLLABLE_SET_H
#define DBUS_POLLABLE_SET_H

#ifndef DOXYGEN_SHOULD_SKIP_THIS

#include <dbus/dbus.h>
#include <dbus/dbus-sysdeps.h>

typedef struct {
    DBusPollable fd;
    unsigned int flags;
} DBusPollableEvent;

// DBusPollableSetClass 和 DBusPollableSet 结构体定义了一个用于管理和监视多个文件描述符的抽象接口。这些结构体使得可以通过定义一组函数指针来实现不同的底层机制（如 poll、epoll、kqueue 等），从而实现对多个文件描述符的高效管理。
typedef struct DBusPollableSet DBusPollableSet;

// DBusPollableSetClass 结构体包含了一组函数指针，用于定义操作 DBusPollableSet 对象的方法。
typedef struct DBusPollableSetClass DBusPollableSetClass;
struct DBusPollableSetClass {
    void (*free)(DBusPollableSet *self); // 释放 DBusPollableSet 对象
    dbus_bool_t (*add)(DBusPollableSet *self, DBusPollable fd, unsigned int flags,
                       dbus_bool_t enabled); // 将文件描述符添加到集合
    void (*remove)(DBusPollableSet *self, DBusPollable fd); // 从集合中移除文件描述符
    void (*enable)(DBusPollableSet *self, DBusPollable fd, unsigned int flags); // 启用对文件描述符的监视
    void (*disable)(DBusPollableSet *self, DBusPollable fd); // 禁用对文件描述符的监视
    int (*poll)(DBusPollableSet *self, DBusPollableEvent *revents, int max_events,
                int timeout_ms); // 轮询文件描述符的事件
};

struct DBusPollableSet {
    DBusPollableSetClass *cls;
};

DBusPollableSet *_dbus_pollable_set_new(int size_hint);

static inline void _dbus_pollable_set_free(DBusPollableSet *self)
{
    (self->cls->free)(self);
}

static inline dbus_bool_t _dbus_pollable_set_add(DBusPollableSet *self, DBusPollable fd, unsigned int flags,
                                                 dbus_bool_t enabled)
{
    return (self->cls->add)(self, fd, flags, enabled);
}

static inline void _dbus_pollable_set_remove(DBusPollableSet *self, DBusPollable fd)
{
    (self->cls->remove)(self, fd);
}

static inline void _dbus_pollable_set_enable(DBusPollableSet *self, DBusPollable fd, unsigned int flags)
{
    (self->cls->enable)(self, fd, flags);
}

static inline void _dbus_pollable_set_disable(DBusPollableSet *self, DBusPollable fd)
{
    (self->cls->disable)(self, fd);
}
// 调用epoll_wait()来轮询文件描述符的事件，获取到就绪的事件
static inline int _dbus_pollable_set_poll(DBusPollableSet *self, DBusPollableEvent *revents, int max_events,
                                          int timeout_ms)
{
    return (self->cls->poll)(self, revents, max_events, timeout_ms);
}

/* concrete implementations, not necessarily built on all platforms */

extern DBusPollableSetClass _dbus_pollable_set_poll_class;
extern DBusPollableSetClass _dbus_pollable_set_epoll_class;

DBusPollableSet *_dbus_pollable_set_poll_new(int size_hint);
DBusPollableSet *_dbus_pollable_set_epoll_new(void);

#endif /* !DOXYGEN_SHOULD_SKIP_THIS */
#endif /* multiple-inclusion guard */
