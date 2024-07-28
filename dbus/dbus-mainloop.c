/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-mainloop.c  Main loop utility
 *
 * Copyright © 2003, 2004  Red Hat, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <config.h>
#include "dbus-mainloop.h"

#ifndef DOXYGEN_SHOULD_SKIP_THIS

#include <dbus/dbus-hash.h>
#include <dbus/dbus-list.h>
#include <dbus/dbus-pollable-set.h>
#include <dbus/dbus-timeout.h>
#include <dbus/dbus-watch.h>

#define MAINLOOP_SPEW 0

struct DBusLoop {
    int refcount; // 引用计数
    /** DBusPollable => dbus_malloc'd DBusList ** of references to DBusWatch */
    DBusHashTable *
            watches; // 哈希表,用于存储文件描述符及其关联的 DBusWatch 对象列表. key 上被监控的文件描述符，value是文件描述符对应的watches结构。为啥是watches结构呢？而不是watch呢？
    DBusPollableSet *
            pollable_set; // linux环境下，就可以理解成epoll_create1创建的epoll实例集合.一个DBusLoop应该是只会有一个epoll_create1创建的epoll实例
    DBusList *timeouts; // 超时事件列表
    // TODO:
    int callback_list_serial; // 回调列表的序列号,用于检测回调列表是否被修改
    int watch_count; // 监视器 (DBusWatch) 的数量
    int timeout_count; // 超时事件的数量
    int depth; /**< number of recursive runs */ // 递归运行的深度
    DBusList *need_dispatch; // 需要分发的连接列表。TODO: 为什么需要这个列表？
    /** TRUE if we will skip a watch next time because it was OOM; becomes
     * FALSE between polling, and dealing with the results of the poll */
    unsigned oom_watch_pending : 1; // 标记是否有由于内存不足而被跳过的监视器
};

typedef struct {
    DBusTimeout *timeout;
    long last_tv_sec;
    long last_tv_usec;
} TimeoutCallback;

#define TIMEOUT_CALLBACK(callback) ((TimeoutCallback *)callback)

static TimeoutCallback *timeout_callback_new(DBusTimeout *timeout)
{
    TimeoutCallback *cb;

    cb = dbus_new(TimeoutCallback, 1);
    if (cb == NULL)
        return NULL;

    cb->timeout = timeout;
    _dbus_get_monotonic_time(&cb->last_tv_sec, &cb->last_tv_usec);
    return cb;
}

static void timeout_callback_free(TimeoutCallback *cb)
{
    dbus_free(cb);
}

static void free_watch_table_entry(void *data)
{
    DBusList **watches = data;
    DBusWatch *watch;

    /* DBusHashTable sometimes calls free_function(NULL) even if you never
   * have NULL as a value */
    if (watches == NULL)
        return;

    for (watch = _dbus_list_pop_first(watches); watch != NULL; watch = _dbus_list_pop_first(watches)) {
        _dbus_watch_unref(watch);
    }

    _dbus_assert(*watches == NULL);
    dbus_free(watches);
}

/**
 * _dbus_loop_new:
 *
 * Creates a new #DBusLoop instance. A #DBusLoop is responsible for managing the
 * main event loop and dispatching events to the appropriate #DBusConnection
 * instances.
 *
 * Returns: a new #DBusLoop instance, or %NULL if the memory allocation failed.
 */
DBusLoop *_dbus_loop_new(void)
{
    DBusLoop *loop;

    // 分配 DBusLoop 结构体的内存
    loop = dbus_new0(DBusLoop, 1);
    if (loop == NULL)
        return NULL;

    // 创建一个哈希表,用于存储文件描述符的监视器 (DBusWatch)
    loop->watches = _dbus_hash_table_new(DBUS_HASH_POLLABLE, NULL, free_watch_table_entry);

    // 创建一个 DBusPollableSet 对象,用于管理需要监视的文件描述符集合
    // 一个epoll 实例对应一个DbusPollableSet实例，也就是一个epoll实例可以管理多个DbusPollable文件描述符
    loop->pollable_set = _dbus_pollable_set_new(0);

    // 如果创建哈希表或 DBusPollableSet 失败,则释放已分配的资源
    if (loop->watches == NULL || loop->pollable_set == NULL) {
        if (loop->watches != NULL)
            _dbus_hash_table_unref(loop->watches);

        if (loop->pollable_set != NULL)
            _dbus_pollable_set_free(loop->pollable_set);

        dbus_free(loop);
        return NULL;
    }

    // 初始化引用计数
    loop->refcount = 1;

    return loop;
}

DBusLoop *_dbus_loop_ref(DBusLoop *loop)
{
    _dbus_assert(loop != NULL);
    _dbus_assert(loop->refcount > 0);

    loop->refcount += 1;

    return loop;
}

void _dbus_loop_unref(DBusLoop *loop)
{
    _dbus_assert(loop != NULL);
    _dbus_assert(loop->refcount > 0);

    loop->refcount -= 1;
    if (loop->refcount == 0) {
        while (loop->need_dispatch) {
            DBusConnection *connection = _dbus_list_pop_first(&loop->need_dispatch);

            dbus_connection_unref(connection);
        }

        _dbus_hash_table_unref(loop->watches);
        _dbus_pollable_set_free(loop->pollable_set);
        dbus_free(loop);
    }
}

/**
 * ensure_watch_table_entry - 确保在给定的 DBusLoop 中为指定的 DBusPollable 文件描述符创建或查找一个表项。
 * @loop: 指向 DBusLoop 结构的指针，该结构表示事件循环。
 * @fd: 指定的 DBusPollable 文件描述符。
 * 
 * 该函数检查在事件循环的 watches 哈希表中是否存在与给定文件描述符相关联的表项。如果存在，则返回该表项的指针。
 * 如果不存在，则创建一个新的表项，插入到哈希表中，并返回新创建的表项的指针。如果内存分配失败或插入哈希表失败，
 * 则返回 NULL。
 * 
 * 返回值:
 * 返回指向 DBusList 指针的指针，表示与给定文件描述符相关联的表项。如果分配或插入失败，返回 NULL。
 */
static DBusList **ensure_watch_table_entry(DBusLoop *loop, DBusPollable fd)
{
    DBusList **watches;

    // 在哈希表中查找与给定文件描述符相关联的表项
    watches = _dbus_hash_table_lookup_pollable(loop->watches, fd);

    // 如果表项不存在，创建一个新的表项
    if (watches == NULL) {
        // 分配一个新的 DBusList 指针数组
        watches = dbus_new0(DBusList *, 1);

        // 如果分配失败，返回 NULL
        if (watches == NULL)
            return watches;

        // 尝试将新的表项插入到哈希表中
        if (!_dbus_hash_table_insert_pollable(loop->watches, fd, watches)) {
            // 如果插入失败，释放分配的内存并将指针置为 NULL
            dbus_free(watches);
            watches = NULL;
        }
    }

    // 返回找到或新创建的表项
    return watches;
}

static void cull_watches_for_invalid_fd(DBusLoop *loop, DBusPollable fd)
{
    DBusList *link;
    DBusList **watches;

    _dbus_warn("invalid request, socket fd %" DBUS_POLLABLE_FORMAT " not open", _dbus_pollable_printable(fd));
    watches = _dbus_hash_table_lookup_pollable(loop->watches, fd);

    if (watches != NULL) {
        for (link = _dbus_list_get_first_link(watches); link != NULL; link = _dbus_list_get_next_link(watches, link))
            _dbus_watch_invalidate(link->data);
    }

    _dbus_hash_table_remove_pollable(loop->watches, fd);
}

static dbus_bool_t gc_watch_table_entry(DBusLoop *loop, DBusList **watches, DBusPollable fd)
{
    /* If watches is already NULL we have nothing to do */
    if (watches == NULL)
        return FALSE;

    /* We can't GC hash table entries if they're non-empty lists */
    if (*watches != NULL)
        return FALSE;

    _dbus_hash_table_remove_pollable(loop->watches, fd);
    return TRUE;
}

/**
 * 更新指定文件描述符的监视器
 *
 * @param loop DBusLoop 对象
 * @param watches DBusWatch 对象的列表指针
 * @param fd 文件描述符
 */
static void refresh_watches_for_fd(DBusLoop *loop, DBusList **watches, DBusPollable fd)
{
    DBusList *link;
    unsigned int flags = 0;
    dbus_bool_t interested = FALSE;

    // 断言文件描述符是有效的
    _dbus_assert(_dbus_pollable_is_valid(fd));

    // 如果传入的监视器列表为 NULL，从哈希表中查找
    if (watches == NULL)
        watches = _dbus_hash_table_lookup_pollable(loop->watches, fd);

    /* 我们在第一次调用 _dbus_loop_add_watch 时为 fd 分配了这个列表，并保持它直到不再有任何监视器 */
    // 断言监视器列表不为 NULL
    _dbus_assert(watches != NULL);

    // 遍历监视器列表，检查每个监视器的状态
    for (link = _dbus_list_get_first_link(watches); link != NULL; link = _dbus_list_get_next_link(watches, link)) {
        // 如果监视器启用且上次未因内存不足而失败
        if (dbus_watch_get_enabled(link->data) && !_dbus_watch_get_oom_last_time(link->data)) {
            // 获取监视器的标志位
            flags |= dbus_watch_get_flags(link->data);
            interested = TRUE;
        }
    }

    // 根据监视器状态更新可轮询集合
    if (interested)
        _dbus_pollable_set_enable(loop->pollable_set, fd, flags);
    else
        _dbus_pollable_set_disable(loop->pollable_set, fd);
}

/**
 * @brief 在事件循环中添加一个监视器
 *
 * 这个函数将一个监视器添加到事件循环中，并确保相应的文件描述符在事件循环的监视器表中有一个条目。
 *
 * @param loop 指向事件循环的指针
 * @param watch 指向要添加的监视器的指针
 * @returns 如果成功添加监视器，返回 TRUE；否则返回 FALSE
 */
dbus_bool_t _dbus_loop_add_watch(DBusLoop *loop, DBusWatch *watch)
{
    DBusPollable fd;
    DBusList **watches;

    // 获取监视器的文件描述符
    fd = _dbus_watch_get_pollable(watch);
    // 确保文件描述符有效
    _dbus_assert(_dbus_pollable_is_valid(fd));

    // 确保在监视器表中有该文件描述符的条目
    watches = ensure_watch_table_entry(loop, fd);

    // 如果条目为空，返回 FALSE
    if (watches == NULL)
        return FALSE;

    // 尝试将监视器添加到该条目中
    if (!_dbus_list_append(watches, _dbus_watch_ref(watch))) {
        // 如果添加失败，释放监视器引用并清理条目
        _dbus_watch_unref(watch);
        gc_watch_table_entry(loop, watches, fd);
        return FALSE;
    }

    // TODO 不懂为啥要这样判断
    if (_dbus_list_length_is_one(watches)) {
        // 尝试将文件描述符添加到事件循环的 pollable 集合中
        if (!_dbus_pollable_set_add(loop->pollable_set, fd, dbus_watch_get_flags(watch),
                                    dbus_watch_get_enabled(watch))) {
            // 如果添加失败，移除文件描述符对应的监视器表条目
            _dbus_hash_table_remove_pollable(loop->watches, fd);
            return FALSE;
        }
    } else {
        // 如果不是第一个监视器，刷新该文件描述符的所有监视器
        refresh_watches_for_fd(loop, watches, fd);
    }

    // 更新事件循环的回调列表序列号和监视器计数
    loop->callback_list_serial += 1;
    loop->watch_count += 1;
    return TRUE;
}

void _dbus_loop_toggle_watch(DBusLoop *loop, DBusWatch *watch)
{
    refresh_watches_for_fd(loop, NULL, _dbus_watch_get_pollable(watch));
}

void _dbus_loop_remove_watch(DBusLoop *loop, DBusWatch *watch)
{
    DBusList **watches;
    DBusList *link;
    DBusPollable fd;

    /* This relies on people removing watches before they invalidate them,
   * which has been safe since fd.o #33336 was fixed. Assert about it
   * so we don't regress. */
    fd = _dbus_watch_get_pollable(watch);
    _dbus_assert(_dbus_pollable_is_valid(fd));

    watches = _dbus_hash_table_lookup_pollable(loop->watches, fd);

    if (watches != NULL) {
        link = _dbus_list_get_first_link(watches);
        while (link != NULL) {
            DBusList *next = _dbus_list_get_next_link(watches, link);
            DBusWatch *this = link->data;

            if (this == watch) {
                _dbus_list_remove_link(watches, link);
                loop->callback_list_serial += 1;
                loop->watch_count -= 1;
                _dbus_watch_unref(this);

                /* if that was the last watch for that fd, drop the hash table
               * entry, and stop reserving space for it in the socket set */
                if (gc_watch_table_entry(loop, watches, fd)) {
                    _dbus_pollable_set_remove(loop->pollable_set, fd);
                }

                return;
            }

            link = next;
        }
    }

    _dbus_warn("could not find watch %p to remove", watch);
}

dbus_bool_t _dbus_loop_add_timeout(DBusLoop *loop, DBusTimeout *timeout)
{
    TimeoutCallback *tcb;

    tcb = timeout_callback_new(timeout);
    if (tcb == NULL)
        return FALSE;

    if (_dbus_list_append(&loop->timeouts, tcb)) {
        loop->callback_list_serial += 1;
        loop->timeout_count += 1;
    } else {
        timeout_callback_free(tcb);
        return FALSE;
    }

    return TRUE;
}

void _dbus_loop_remove_timeout(DBusLoop *loop, DBusTimeout *timeout)
{
    DBusList *link;

    link = _dbus_list_get_first_link(&loop->timeouts);
    while (link != NULL) {
        DBusList *next = _dbus_list_get_next_link(&loop->timeouts, link);
        TimeoutCallback *this = link->data;

        if (this->timeout == timeout) {
            _dbus_list_remove_link(&loop->timeouts, link);
            loop->callback_list_serial += 1;
            loop->timeout_count -= 1;
            timeout_callback_free(this);

            return;
        }

        link = next;
    }

    _dbus_warn("could not find timeout %p to remove", timeout);
}

/* Convolutions from GLib, there really must be a better way
 * to do this.
 */
static dbus_bool_t check_timeout(long tv_sec, long tv_usec, TimeoutCallback *tcb, int *timeout)
{
    long sec_remaining;
    long msec_remaining;
    long expiration_tv_sec;
    long expiration_tv_usec;
    long interval_seconds;
    long interval_milliseconds;
    int interval;

    /* I'm pretty sure this function could suck (a lot) less */

    interval = dbus_timeout_get_interval(tcb->timeout);

    interval_seconds = interval / 1000L;
    interval_milliseconds = interval % 1000L;

    expiration_tv_sec = tcb->last_tv_sec + interval_seconds;
    expiration_tv_usec = tcb->last_tv_usec + interval_milliseconds * 1000;
    if (expiration_tv_usec >= 1000000) {
        expiration_tv_usec -= 1000000;
        expiration_tv_sec += 1;
    }

    sec_remaining = expiration_tv_sec - tv_sec;
    msec_remaining = (expiration_tv_usec - tv_usec) / 1000L;

#if MAINLOOP_SPEW
    _dbus_verbose("Interval is %ld seconds %ld msecs\n", interval_seconds, interval_milliseconds);
    _dbus_verbose("Now is  %lu seconds %lu usecs\n", tv_sec, tv_usec);
    _dbus_verbose("Last is %lu seconds %lu usecs\n", tcb->last_tv_sec, tcb->last_tv_usec);
    _dbus_verbose("Exp is  %lu seconds %lu usecs\n", expiration_tv_sec, expiration_tv_usec);
    _dbus_verbose("Pre-correction, sec_remaining %ld msec_remaining %ld\n", sec_remaining, msec_remaining);
#endif

    /* We do the following in a rather convoluted fashion to deal with
   * the fact that we don't have an integral type big enough to hold
   * the difference of two timevals in milliseconds.
   */
    if (sec_remaining < 0 || (sec_remaining == 0 && msec_remaining < 0)) {
        *timeout = 0;
    } else {
        if (msec_remaining < 0) {
            msec_remaining += 1000;
            sec_remaining -= 1;
        }

        if (sec_remaining > (_DBUS_INT_MAX / 1000) || msec_remaining > _DBUS_INT_MAX)
            *timeout = _DBUS_INT_MAX;
        else
            *timeout = sec_remaining * 1000 + msec_remaining;
    }

    if (*timeout > interval) {
        /* This indicates that the system clock probably moved backward */
        _dbus_verbose("System clock set backward! Resetting timeout.\n");

        tcb->last_tv_sec = tv_sec;
        tcb->last_tv_usec = tv_usec;

        *timeout = interval;
    }

#if MAINLOOP_SPEW
    _dbus_verbose("  timeout expires in %d milliseconds\n", *timeout);
#endif

    return *timeout == 0;
}

// 处理 D-Bus 连接上的消息
dbus_bool_t _dbus_loop_dispatch(DBusLoop *loop)
{
#if MAINLOOP_SPEW
    _dbus_verbose("  %d connections to dispatch\n", _dbus_list_get_length(&loop->need_dispatch));
#endif

    // 如果没有需要处理的消息,直接返回 FALSE
    if (loop->need_dispatch == NULL)
        return FALSE;

next:
    // 遍历需要处理的连接列表
    while (loop->need_dispatch != NULL) {
        // 取出第一个连接进行处理
        // 注意，不是消息，是连接（connection），因为一个connection会接受很多的消息
        DBusConnection *connection = _dbus_list_pop_first(&loop->need_dispatch);

        while (TRUE) {
            DBusDispatchStatus status;

            // 分发连接上的待处理消息
            status = dbus_connection_dispatch(connection);

            // 如果所有消息都已处理完毕,则释放连接对象并继续处理下一个连接
            if (status == DBUS_DISPATCH_COMPLETE) {
                dbus_connection_unref(connection);
                goto next;
            } else {
                // 如果由于内存不足而无法处理所有消息,则等待内存可用
                if (status == DBUS_DISPATCH_NEED_MEMORY)
                    _dbus_wait_for_memory();
            }
        }
    }

    // 如果至少有一个连接被分发过,则返回 TRUE
    return TRUE;
}

/**
 * 将DBusConnection添加到需要调度的列表中
 *
 * @param loop 事件循环对象，DBusLoop类型
 * @param connection 需要添加到调度队列的连接，DBusConnection类型
 * @return 如果成功将连接添加到调度队列，则返回TRUE，否则返回FALSE
 */
dbus_bool_t _dbus_loop_queue_dispatch(DBusLoop *loop, DBusConnection *connection)
{
    // 尝试将连接添加到需要调度的列表中
    if (_dbus_list_append(&loop->need_dispatch, connection)) {
        // 如果添加成功，增加连接的引用计数
        dbus_connection_ref(connection);
        // 返回TRUE表示成功
        return TRUE;
    } else {
        // 如果添加失败，返回FALSE
        return FALSE;
    }
}

/* Returns TRUE if we invoked any timeouts or have ready file
 * descriptors, which is just used in test code as a debug hack
 */
// loop_iterate的作用就是调用watch？
dbus_bool_t _dbus_loop_iterate(DBusLoop *loop, dbus_bool_t block)
{
#define N_STACK_DESCRIPTORS 64
    dbus_bool_t retval;
    DBusPollableEvent ready_fds[N_STACK_DESCRIPTORS];
    int i;
    DBusList *link;
    int n_ready;
    int initial_serial;
    long timeout;
    int orig_depth;

    retval = FALSE;

    orig_depth = loop->depth;

    // 打印调试信息
#if MAINLOOP_SPEW
    _dbus_verbose("Iteration block=%d depth=%d timeout_count=%d watch_count=%d\n", block, loop->depth,
                  loop->timeout_count, loop->watch_count);
#endif

    // 最开始在main函数中已经添加了一个reload_pipe[0]描述符进行监视
    // 如果目前还没有添加任何文件描述符或超时事件进行监视,直接返回
    // 目前还不确定最开始会不会进入这个goto
    // 先不管吧
    if (_dbus_hash_table_get_n_entries(loop->watches) == 0 && loop->timeouts == NULL)
        goto next_iteration;

    // 下面是开始处理超时事件
    // 感觉暂时是不需要这些，先不看
    timeout = -1;
    // 存在超时的事件
    if (loop->timeout_count > 0) {
        long tv_sec;
        long tv_usec;

        _dbus_get_monotonic_time(&tv_sec, &tv_usec);

        // 获取到排在最前面的第一个超时的事件
        // 看起来是遍历链表
        link = _dbus_list_get_first_link(&loop->timeouts);
        while (link != NULL) {
            DBusList *next = _dbus_list_get_next_link(&loop->timeouts, link);
            TimeoutCallback *tcb = link->data;

            if (dbus_timeout_get_enabled(tcb->timeout)) {
                int msecs_remaining;

                if (_dbus_timeout_needs_restart(tcb->timeout)) {
                    tcb->last_tv_sec = tv_sec;
                    tcb->last_tv_usec = tv_usec;
                    _dbus_timeout_restarted(tcb->timeout);
                }

                check_timeout(tv_sec, tv_usec, tcb, &msecs_remaining);

                if (timeout < 0)
                    timeout = msecs_remaining;
                else
                    timeout = MIN(msecs_remaining, timeout);

#if MAINLOOP_SPEW
                _dbus_verbose("  timeout added, %d remaining, aggregate timeout %ld\n", msecs_remaining, timeout);
#endif

                _dbus_assert(timeout >= 0);
            }
#if MAINLOOP_SPEW
            else {
                _dbus_verbose("  skipping disabled timeout\n");
            }
#endif

            link = next;
        }
    }

    // 如果不需要阻塞或有挂起的消息需要分发,将超时值设置为0
    if (!block || loop->need_dispatch != NULL) {
        timeout = 0;
#if MAINLOOP_SPEW
        _dbus_verbose("  timeout is 0 as we aren't blocking\n");
#endif
    }

    // 如果上次有文件描述符事件由于内存不足而被跳过,则将超时值设置为较小的值,以尽快重新启用该事件
    if (loop->oom_watch_pending)
        timeout = MIN(timeout, _dbus_get_oom_wait());

#if MAINLOOP_SPEW
    _dbus_verbose("  polling on %d descriptors timeout %ld\n", _DBUS_N_ELEMENTS(ready_fds), timeout);
#endif

    // 使用 epoll_wait 等待就绪的文件描述符事件,直到超时或有事件发生
    n_ready = _dbus_pollable_set_poll(loop->pollable_set, ready_fds, _DBUS_N_ELEMENTS(ready_fds), timeout);

    // 重新启用上次由于内存不足而被跳过的文件描述符事件
    if (loop->oom_watch_pending) {
        DBusHashIter hash_iter;

        loop->oom_watch_pending = FALSE;

        _dbus_hash_iter_init(loop->watches, &hash_iter);

        while (_dbus_hash_iter_next(&hash_iter)) {
            DBusList **watches;
            DBusPollable fd;
            dbus_bool_t changed;

            changed = FALSE;
            fd = _dbus_hash_iter_get_pollable_key(&hash_iter);
            watches = _dbus_hash_iter_get_value(&hash_iter);

            for (link = _dbus_list_get_first_link(watches); link != NULL;
                 link = _dbus_list_get_next_link(watches, link)) {
                DBusWatch *watch = link->data;

                if (_dbus_watch_get_oom_last_time(watch)) {
                    _dbus_watch_set_oom_last_time(watch, FALSE);
                    changed = TRUE;
                }
            }

            if (changed)
                refresh_watches_for_fd(loop, watches, fd);
        }

        retval = TRUE; // 返回 TRUE 以继续循环,因为我们不知道被跳过的事件是否已经就绪
    }

    // TODO
    // 是和多线程环境中确保回调函数列表一致性相关？
    initial_serial = loop->callback_list_serial;

    // 处理到期的超时事件
    if (loop->timeout_count > 0) {
        long tv_sec;
        long tv_usec;

        _dbus_get_monotonic_time(&tv_sec, &tv_usec);

        link = _dbus_list_get_first_link(&loop->timeouts);
        while (link != NULL) {
            DBusList *next = _dbus_list_get_next_link(&loop->timeouts, link);
            TimeoutCallback *tcb = link->data;

            // 如果有新的事件源被添加或删除,或者循环深度发生变化,则重新开始新的一轮迭代
            if (initial_serial != loop->callback_list_serial)
                goto next_iteration;

            if (loop->depth != orig_depth)
                goto next_iteration;

            if (dbus_timeout_get_enabled(tcb->timeout)) {
                int msecs_remaining;

                if (check_timeout(tv_sec, tv_usec, tcb, &msecs_remaining)) {
                    // 保存上次回调时间,并调用超时事件的回调函数
                    tcb->last_tv_sec = tv_sec;
                    tcb->last_tv_usec = tv_usec;

#if MAINLOOP_SPEW
                    _dbus_verbose("  invoking timeout\n");
#endif

                    dbus_timeout_handle(tcb->timeout);

                    retval = TRUE;
                } else {
#if MAINLOOP_SPEW
                    _dbus_verbose("  timeout has not expired\n");
#endif
                }
            }
#if MAINLOOP_SPEW
            else {
                _dbus_verbose("  skipping invocation of disabled timeout\n");
            }
#endif

            link = next;
        }
    }

    // 目前有个疑惑，最开始的那个服务端监控socket在哪里创建的？目前还没找到
    // 先不管这个吧
    // 有新的连接来了？
    if (n_ready > 0) {
        for (i = 0; i < n_ready; i++) {
            DBusList **watches;
            DBusList *next;
            unsigned int condition;
            dbus_bool_t any_oom;

            // 如果有新的事件源被添加或删除,或者循环深度发生变化,则重新开始新的一轮迭代
            if (initial_serial != loop->callback_list_serial)
                goto next_iteration;

            // TODO: 不懂这个有啥用
            if (loop->depth != orig_depth)
                goto next_iteration;

            _dbus_assert(ready_fds[i].flags != 0);

            // 如果文件描述符无效,则删除相关的监视器
            if (_DBUS_UNLIKELY(ready_fds[i].flags & _DBUS_WATCH_NVAL)) {
                cull_watches_for_invalid_fd(loop, ready_fds[i].fd);
                goto next_iteration;
            }
            // 这里flags 为1,也就是readable事件.这个fd感觉是系统总线的fd,所以这里是readable事件
            condition = ready_fds[i].flags;
            _dbus_assert((condition & _DBUS_WATCH_NVAL) == 0);

            // 如果条件为0,则跳过该事件
            if (condition == 0)
                continue;

            // 查找与该服务端文件描述符相关的监视器
            // 第一次调用时，这个应该就是服务端的fd
            // 但是这个fd是啥回事创建的呢？到目前为止，只创建过一个reload_pipe fd
            // 任何客户端/服务进程连接过来，应该都是被同一个server监控？fd是3
            watches = _dbus_hash_table_lookup_pollable(loop->watches, ready_fds[i].fd);

            if (watches == NULL)
                continue;

            any_oom = FALSE;

            // 一个服务端文件描述符可以监视多个客户端的连接,因此需要遍历所有监视器
            // 调用与该文件描述符相关的所有监视器的回调函数
            for (link = _dbus_list_get_first_link(watches); link != NULL; link = next) {
                DBusWatch *watch = link->data;

                next = _dbus_list_get_next_link(watches, link);

                if (dbus_watch_get_enabled(watch)) {
                    dbus_bool_t oom;
                    // 这里的回调函数是socket_handle_watch
                    oom = !dbus_watch_handle(watch, condition);

                    if (oom) {
                        _dbus_watch_set_oom_last_time(watch, TRUE);
                        loop->oom_watch_pending = TRUE;
                        any_oom = TRUE;
                    }

#if MAINLOOP_SPEW
                    _dbus_verbose("  Invoked watch, oom = %d\n", oom);
#endif
                    retval = TRUE;

                    // 如果有新的事件源被添加或删除,或者循环深度发生变化,则重新开始新的一轮迭代
                    if (initial_serial != loop->callback_list_serial || loop->depth != orig_depth) {
                        if (any_oom)
                            refresh_watches_for_fd(loop, NULL, ready_fds[i].fd);

                        goto next_iteration;
                    }
                }
            }

            // 如果有任何监视器由于内存不足而被跳过,则重新启用该文件描述符的监视器
            if (any_oom)
                refresh_watches_for_fd(loop, watches, ready_fds[i].fd);
        }
    }

next_iteration:
#if MAINLOOP_SPEW
    _dbus_verbose("  moving to next iteration\n");
#endif

    // 开始处理收到的消息
    if (_dbus_loop_dispatch(loop))
        retval = TRUE;

#if MAINLOOP_SPEW
    _dbus_verbose("Returning %d\n", retval);
#endif

    return retval;
}

void _dbus_loop_run(DBusLoop *loop)
{
    int our_exit_depth;

    // TODO
    // 这个loop->depth是哪个地方设置的？
    _dbus_assert(loop->depth >= 0);

    _dbus_loop_ref(loop);

    // 这个循环深度是在哪里设置的？
    our_exit_depth = loop->depth;
    loop->depth += 1;

    _dbus_verbose("Running main loop, depth %d -> %d\n", loop->depth - 1, loop->depth);

    while (loop->depth != our_exit_depth)
        _dbus_loop_iterate(loop, TRUE);

    _dbus_loop_unref(loop);
}

void _dbus_loop_quit(DBusLoop *loop)
{
    _dbus_assert(loop->depth > 0);

    loop->depth -= 1;

    _dbus_verbose("Quit main loop, depth %d -> %d\n", loop->depth + 1, loop->depth);
}

int _dbus_get_oom_wait(void)
{
#ifdef DBUS_ENABLE_EMBEDDED_TESTS
    /* make tests go fast */
    return 0;
#else
    return 500;
#endif
}

void _dbus_wait_for_memory(void)
{
    _dbus_verbose("Waiting for more memory\n");
    _dbus_sleep_milliseconds(_dbus_get_oom_wait());
}

#endif /* !DOXYGEN_SHOULD_SKIP_THIS */
