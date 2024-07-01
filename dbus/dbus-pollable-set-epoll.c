/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-pollable-set-epoll.c - a pollable set implemented via Linux epoll(4)
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

#include <config.h>
#include "dbus-pollable-set.h"

#include <dbus/dbus-internals.h>
#include <dbus/dbus-sysdeps.h>

#ifndef __linux__
#error This file is for Linux epoll(4)
#endif

#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

#ifndef DOXYGEN_SHOULD_SKIP_THIS

// 这种可以实现C语言中的继承
typedef struct {
    DBusPollableSet parent;
    int epfd;
} DBusPollableSetEpoll;

static inline DBusPollableSetEpoll *socket_set_epoll_cast(DBusPollableSet *set)
{
    _dbus_assert(set->cls == &_dbus_pollable_set_epoll_class);
    return (DBusPollableSetEpoll *)set;
}

/* this is safe to call on a partially-allocated socket set */
static void socket_set_epoll_free(DBusPollableSet *set)
{
    DBusPollableSetEpoll *self = socket_set_epoll_cast(set);

    if (self == NULL)
        return;

    if (self->epfd != -1)
        close(self->epfd);

    dbus_free(self);
}

DBusPollableSet *_dbus_pollable_set_epoll_new(void)
{
    DBusPollableSetEpoll *self;

    // 分配并清零一个 DBusPollableSetEpoll 结构体
    self = dbus_new0(DBusPollableSetEpoll, 1);

    // 如果分配失败，返回 NULL
    if (self == NULL)
        return NULL;

    // 初始化父类指针，指向 epoll 类
    self->parent.cls = &_dbus_pollable_set_epoll_class;

    // 尝试创建 epoll 文件描述符，设置为自动关闭模式
    self->epfd = epoll_create1(EPOLL_CLOEXEC);

    // 如果 epoll_create1 调用失败，尝试使用较老的 epoll_create
    if (self->epfd == -1) {
        int flags;

        /* 尽管 size hint 在较新的内核版本中被忽略，但在某些版本中必须为正值，
         * 所以选择一个任意的正值；它只是一个提示，不是限制 */
        self->epfd = epoll_create(42);

        // 获取文件描述符标志
        flags = fcntl(self->epfd, F_GETFD, 0);

        // 如果获取成功，设置文件描述符为自动关闭模式
        if (flags != -1)
            fcntl(self->epfd, F_SETFD, flags | FD_CLOEXEC);
    }

    // 如果 epoll 文件描述符创建仍然失败，释放已分配的内存并返回 NULL
    if (self->epfd == -1) {
        socket_set_epoll_free((DBusPollableSet *)self);
        return NULL;
    }

    // 成功创建，返回指向 DBusPollableSet 的指针
    return (DBusPollableSet *)self;
}

static uint32_t watch_flags_to_epoll_events(unsigned int flags)
{
    uint32_t events = 0;

    // 如果 flags 包含 DBUS_WATCH_READABLE 标志，添加 EPOLLIN 事件
    // 有读事件
    if (flags & DBUS_WATCH_READABLE)
        events |= EPOLLIN;

    // 如果 flags 包含 DBUS_WATCH_WRITABLE 标志，添加 EPOLLOUT 事件
    // 有写事件
    if (flags & DBUS_WATCH_WRITABLE)
        events |= EPOLLOUT;

    // 返回转换后的 epoll 事件标志
    return events;
}

static unsigned int epoll_events_to_watch_flags(uint32_t events)
{
    short flags = 0;

    if (events & EPOLLIN)
        flags |= DBUS_WATCH_READABLE;
    if (events & EPOLLOUT)
        flags |= DBUS_WATCH_WRITABLE;
    if (events & EPOLLHUP)
        flags |= DBUS_WATCH_HANGUP;
    if (events & EPOLLERR)
        flags |= DBUS_WATCH_ERROR;

    return flags;
}

static dbus_bool_t socket_set_epoll_add(DBusPollableSet *set, DBusPollable fd, unsigned int flags, dbus_bool_t enabled)
{
    // 将通用的 DBusPollableSet 类型指针转换为具体的 DBusPollableSetEpoll 类型指针
    DBusPollableSetEpoll *self = socket_set_epoll_cast(set);
    struct epoll_event event;
    int err;

    // 初始化 event 结构体为零
    _DBUS_ZERO(event);
    event.data.fd = fd;

    // 根据 enabled 参数设置 event.events 字段
    if (enabled) {
        // 如果 enabled 为真，设置 event.events 为根据 flags 转换的 epoll 事件
        event.events = watch_flags_to_epoll_events(flags);
    } else {
        // 如果 enabled 为假，设置事件为 EPOLLET（边缘触发），用于在内核数据结构中保留空间
        event.events = EPOLLET;
    }

    // 尝试将文件描述符 fd 添加到 epoll 实例中
    if (epoll_ctl(self->epfd, EPOLL_CTL_ADD, fd, &event) == 0)
        return TRUE; // 成功添加返回 TRUE

    // 如果添加失败，获取并处理错误代码
    err = errno;
    switch (err) {
        case ENOMEM:
        case ENOSPC:
            // 对于内存不足或空间不足的错误，静默处理，调用者预期会处理这种情况
            break;

        case EBADF:
            // 处理无效文件描述符错误
            _dbus_warn("Bad fd %d", fd);
            break;

        case EEXIST:
            // 处理文件描述符已存在错误
            _dbus_warn("fd %d added and then added again", fd);
            break;

        default:
            // 处理其他错误
            _dbus_warn("Misc error when trying to watch fd %d: %s", fd, strerror(err));
            break;
    }

    // 返回 FALSE 表示添加失败
    return FALSE;
}

static void socket_set_epoll_enable(DBusPollableSet *set, DBusPollable fd, unsigned int flags)
{
    DBusPollableSetEpoll *self = socket_set_epoll_cast(set);
    struct epoll_event event;
    int err;

    _DBUS_ZERO(event);
    event.data.fd = fd;
    event.events = watch_flags_to_epoll_events(flags);

    if (epoll_ctl(self->epfd, EPOLL_CTL_MOD, fd, &event) == 0)
        return;

    err = errno;

    /* Enabling a file descriptor isn't allowed to fail, even for OOM, so we
   * do our best to avoid all of these. */
    switch (err) {
        case EBADF:
            _dbus_warn("Bad fd %d", fd);
            break;

        case ENOENT:
            _dbus_warn("fd %d enabled before it was added", fd);
            break;

        case ENOMEM:
            _dbus_warn("Insufficient memory to change watch for fd %d", fd);
            break;

        default:
            _dbus_warn("Misc error when trying to watch fd %d: %s", fd, strerror(err));
            break;
    }
}

static void socket_set_epoll_disable(DBusPollableSet *set, DBusPollable fd)
{
    DBusPollableSetEpoll *self = socket_set_epoll_cast(set);
    struct epoll_event event;
    int err;

    /* The naive thing to do would be EPOLL_CTL_DEL, but that'll probably
   * free resources in the kernel. When we come to do socket_set_epoll_enable,
   * there might not be enough resources to bring it back!
   *
   * The next idea you might have is to set the flags to 0. However, events
   * always trigger on EPOLLERR and EPOLLHUP, even if libdbus isn't actually
   * delivering them to a DBusWatch. Because epoll is level-triggered by
   * default, we'll busy-loop on an unhandled error or hangup; not good.
   *
   * So, let's set it to be edge-triggered: then the worst case is that
   * we return from poll immediately on one iteration, ignore it because no
   * watch is enabled, then go back to normal. When we re-enable a watch
   * we'll switch back to level-triggered and be notified again (verified to
   * work on 2.6.32). Compile this file with -DTEST_BEHAVIOUR_OF_EPOLLET for
   * test code.
   */
    _DBUS_ZERO(event);
    event.data.fd = fd;
    event.events = EPOLLET;

    if (epoll_ctl(self->epfd, EPOLL_CTL_MOD, fd, &event) == 0)
        return;

    err = errno;
    _dbus_warn("Error when trying to watch fd %d: %s", fd, strerror(err));
}

static void socket_set_epoll_remove(DBusPollableSet *set, DBusPollable fd)
{
    DBusPollableSetEpoll *self = socket_set_epoll_cast(set);
    int err;
    /* Kernels < 2.6.9 require a non-NULL struct pointer, even though its
   * contents are ignored */
    struct epoll_event dummy;
    _DBUS_ZERO(dummy);

    if (epoll_ctl(self->epfd, EPOLL_CTL_DEL, fd, &dummy) == 0)
        return;

    err = errno;
    _dbus_warn("Error when trying to remove fd %d: %s", fd, strerror(err));
}

/* Optimally, this should be the same as in DBusLoop: we use it to translate
 * between struct epoll_event and DBusSocketEvent without allocating heap
 * memory. */
#define N_STACK_DESCRIPTORS 64

// 这个看起来就是阻塞，收集就绪的事件的描述符和事件类型
static int socket_set_epoll_poll(DBusPollableSet *set, DBusPollableEvent *revents, int max_events, int timeout_ms)
{
    DBusPollableSetEpoll *self = socket_set_epoll_cast(set);
    struct epoll_event events[N_STACK_DESCRIPTORS];
    int n_ready;
    int i;

    _dbus_assert(max_events > 0);

    // 就绪事件的数量
    n_ready = epoll_wait(self->epfd, events, MIN(_DBUS_N_ELEMENTS(events), max_events), timeout_ms);

    if (n_ready <= 0)
        return n_ready;

    for (i = 0; i < n_ready; i++) {
        // 就绪事件对应的描述符
        revents[i].fd = events[i].data.fd;
        // 就绪事件的类型
        revents[i].flags = epoll_events_to_watch_flags(events[i].events);
    }

    return n_ready;
}

DBusPollableSetClass _dbus_pollable_set_epoll_class = { socket_set_epoll_free,    socket_set_epoll_add,
                                                        socket_set_epoll_remove,  socket_set_epoll_enable,
                                                        socket_set_epoll_disable, socket_set_epoll_poll };

#ifdef TEST_BEHAVIOUR_OF_EPOLLET
/* usage: cat /dev/null | ./epoll
 *
 * desired output:
 * ctl ADD: 0
 * wait for HUP, edge-triggered: 1
 * wait for HUP again: 0
 * ctl MOD: 0
 * wait for HUP: 1
 */

#include <sys/epoll.h>

#include <stdio.h>

int main(void)
{
    struct epoll_event input;
    struct epoll_event output;
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    int fd = 0; /* stdin */
    int ret;

    _DBUS_ZERO(input);

    input.events = EPOLLHUP | EPOLLET;
    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &input);
    printf("ctl ADD: %d\n", ret);

    ret = epoll_wait(epfd, &output, 1, -1);
    printf("wait for HUP, edge-triggered: %d\n", ret);

    ret = epoll_wait(epfd, &output, 1, 1);
    printf("wait for HUP again: %d\n", ret);

    input.events = EPOLLHUP;
    ret = epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &input);
    printf("ctl MOD: %d\n", ret);

    ret = epoll_wait(epfd, &output, 1, -1);
    printf("wait for HUP: %d\n", ret);

    return 0;
}

#endif /* TEST_BEHAVIOUR_OF_EPOLLET */

#endif /* !DOXYGEN_SHOULD_SKIP_THIS */
