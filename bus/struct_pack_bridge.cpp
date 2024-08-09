
#include "dbus/dbus-timeout.h"
#include "dbus/dbus-watch.h"
#include "dbus_serialization.h"
#include "dbus/dbus-auth.h"
#include "dbus/dbus-dataslot.h"
#include "dbus/dbus-marshal-validate.h"
#include "dbus/dbus-message-internal.h"
#include "dbus/dbus-resources.h"
#include "dbus/dbus-string.h"
#include "dbus/dbus-transport.h"
#include <compare>
#include <dbus/dbus-message-private.h>
#include "dbus/dbus-marshal-header.h"
#include "dbus/dbus-sysdeps.h"
#include <ylt/struct_pack.hpp>
#include <vector>
#include <string>
#include <cstring>
#include <ylt/struct_pack/derived_marco.hpp>
#include <ylt/struct_pack/reflection.hpp>
#include "dbus/dbus-transport-protected.h"

STRUCT_PACK_REFL(DBusAtomic, value);

struct SerializableDBusString : public DBusString {
    unsigned int dummy_bit1; /**< placeholder */
    unsigned int dummy_bit2; /**< placeholder */
    unsigned int dummy_bit3; /**< placeholder */
    unsigned int dummy_bits; /**< placeholder */
};
STRUCT_PACK_REFL(SerializableDBusString, dummy1, dummy2, dummy3, dummy_bit1, dummy_bit2, dummy_bit3, dummy_bits);
// STRUCT_PACK_DERIVED_DECL(DBusString, SerializableDBusString);

STRUCT_PACK_REFL(DBusHeaderField, value_pos);

struct SerializableDBusHeader : public DBusHeader {
    SerializableDBusString data;
    dbus_uint32_t padding;
    dbus_uint32_t byte_order;
};
STRUCT_PACK_REFL(SerializableDBusHeader, data, fields, padding, byte_order);
// STRUCT_PACK_DERIVED_DECL(DBusHeader, SerializableDBusHeader);

struct SerializableDBusCounter {
    int refcount; /**< reference count */

    long size_value; /**< current size counter value */
    long unix_fd_value; /**< current unix fd counter value */

#ifdef DBUS_ENABLE_STATS
    long peak_size_value; /**< largest ever size counter value */
    long peak_unix_fd_value; /**< largest ever unix fd counter value */
#endif

    long notify_size_guard_value; /**< call notify function when crossing this size value */
    long notify_unix_fd_guard_value; /**< call notify function when crossing this unix fd value */

    DBusCounterNotifyFunction notify_function; /**< notify function */
    void *notify_data; /**< data for notify function */
    dbus_bool_t notify_pending; /**< TRUE if the guard value has been crossed */
};
STRUCT_PACK_REFL(SerializableDBusCounter, refcount, size_value, unix_fd_value, notify_size_guard_value,
                 notify_unix_fd_guard_value, notify_function, notify_data, notify_pending);

struct SerializableDBusDataSlot : public DBusDataSlot {
    std::string data;
    std::string free_data_func;
};
STRUCT_PACK_REFL(SerializableDBusDataSlot, data, free_data_func);
// STRUCT_PACK_DERIVED_DECL(DBusDataSlot, SerializableDBusDataSlot);

struct SerializableDBusMessage : public DBusMessage {
    SerializableDBusHeader header;
    SerializableDBusString body;
    unsigned int locked;
    unsigned int in_cache;
    std::vector<SerializableDBusCounter> counters;
    dbus_uint32_t changed_stamp;
    std::vector<DBusDataSlot> slot_list;
    std::vector<int> unix_fds;
};
STRUCT_PACK_REFL(SerializableDBusMessage, refcount, header, body, locked, in_cache, counters, size_counter_delta,
                 changed_stamp, slot_list, generation, unix_fds, n_unix_fds, n_unix_fds_allocated,
                 unix_fd_counter_delta);
// STRUCT_PACK_DERIVED_DECL(DBusMessage, SerializableDBusMessage);

struct SerializableDBusMessageLoader : public DBusMessageLoader {
    SerializableDBusString data;
    std::vector<SerializableDBusMessage> messages;
    unsigned int corrupted;
    unsigned int buffer_outstanding;
    unsigned int unix_fds_outstanding;

    std::vector<int> unix_fds;
};
STRUCT_PACK_REFL(SerializableDBusMessageLoader, refcount, data, messages, max_message_size, corruption_reason,
                 corrupted, buffer_outstanding, unix_fds_outstanding, unix_fds, n_unix_fds_allocated, n_unix_fds,
                 unix_fds_change, unix_fds_change_data);
// STRUCT_PACK_DERIVED_DECL(DBusMessageLoader, SerializableDBusMessageLoader);

struct SerializableDBusAuthStateData {
    const char *name; /**< Name of the state */
    std::string handler; /**< State function for this state */
};
STRUCT_PACK_REFL(SerializableDBusAuthStateData, name, handler);

struct SerializableDBusAuthMechanismHandler {
    std::string mechanism;
    std::string server_data_func;
    std::string server_encode_func;
    std::string server_decode_func;
    std::string server_shutdown_func;
    std::string client_initial_response_func;
    std::string client_data_func;
    std::string client_encode_func;
    std::string client_decode_func;
    std::string client_shutdown_func;
};
STRUCT_PACK_REFL(SerializableDBusAuthMechanismHandler, mechanism, server_data_func, server_encode_func,
                 server_decode_func, server_shutdown_func, client_initial_response_func, client_data_func,
                 client_encode_func, client_decode_func, client_shutdown_func);

struct SerializableDBusCredentials {
    int refcount;
    dbus_uid_t unix_uid;
    dbus_gid_t *unix_gids;
    size_t n_unix_gids;
    dbus_pid_t pid;
    std::string windows_sid;
    std::string linux_security_label;
    std::string adt_audit_data;
    dbus_int32_t adt_audit_data_size;
};
STRUCT_PACK_REFL(SerializableDBusCredentials, refcount, unix_uid, unix_gids, n_unix_gids, pid, windows_sid,
                 linux_security_label, adt_audit_data, adt_audit_data_size);

struct SerializableDBusKey {
    dbus_int32_t id;
    long creation_time;
    SerializableDBusString secret;
};
STRUCT_PACK_REFL(SerializableDBusKey, id, creation_time, secret);

struct SerializableDBusKeyring {
    int refcount; /**< Reference count */
    SerializableDBusString directory; /**< Directory the below two items are inside */
    SerializableDBusString filename; /**< Keyring filename */
    SerializableDBusString filename_lock; /**< Name of lockfile */
    SerializableDBusKey keys; /**< Keys loaded from the file */
    int n_keys; /**< Number of keys */
    SerializableDBusCredentials credentials; /**< Credentials containing user the keyring is for */
};
STRUCT_PACK_REFL(SerializableDBusKeyring, refcount, directory, filename, filename_lock, keys, n_keys, credentials);

struct SerializableDBusAuth {
    int refcount; /**< reference count */
    const char *side; /**< Client or server */

    SerializableDBusString incoming; /**< Incoming data buffer */
    SerializableDBusString outgoing; /**< Outgoing data buffer */

    SerializableDBusAuthStateData state; /**< Current protocol state */

    SerializableDBusAuthMechanismHandler mech; /**< Current auth mechanism */

    SerializableDBusString identity; /**< Current identity we're authorizing
                                          *   as.
                                          */

    SerializableDBusCredentials credentials; /**< Credentials read from socket
                                          */

    SerializableDBusCredentials authorized_identity; /**< Credentials that are authorized */

    SerializableDBusCredentials desired_identity; /**< Identity client has requested */

    SerializableDBusString context;
    SerializableDBusKeyring keyring;
    int cookie_id;
    SerializableDBusString challenge;

    std::vector<std::string> allowed_mechs;
    unsigned int needed_memory;
    unsigned int already_got_mechanisms;
    unsigned int already_asked_for_initial_response;
    unsigned int buffer_outstanding;

    unsigned int unix_fd_possible;
    unsigned int unix_fd_negotiated;
};
STRUCT_PACK_REFL(SerializableDBusAuth, refcount, side, incoming, outgoing, state, mech, identity, credentials,
                 authorized_identity, desired_identity, context, keyring, cookie_id, challenge, allowed_mechs,
                 needed_memory, already_got_mechanisms, already_asked_for_initial_response, buffer_outstanding,
                 unix_fd_possible, unix_fd_negotiated);

struct SerializableDBusTransport : public DBusTransport {
    std::vector<DBusTransportVTable> vtable;
    SerializableDBusMessageLoader loader;
    SerializableDBusAuth auth;
    std::vector<SerializableDBusCredentials> credentials;
    SerializableDBusCounter live_messages;
    std::string address;
    std::string expected_guid;
    std::string unix_user_function;
    std::string unix_user_data;
    std::string free_unix_user_data;
    std::string DBusAllowWindowsUserFunction;
    std::string windows_user_data;
    std::string free_windows_user_data;
    unsigned int disconnected;
    unsigned int authenticated;
    unsigned int send_credentials_pending;
    unsigned int receive_credentials_pending;
    unsigned int is_server;
    unsigned int unused_bytes_recovered;
    unsigned int allow_anonymous;
};
STRUCT_PACK_REFL(SerializableDBusTransport, refcount, vtable, loader, auth, credentials, max_live_messages_size,
                 max_live_messages_unix_fds, live_messages, address, expected_guid, unix_user_function, unix_user_data,
                 free_unix_user_data, windows_user_function, windows_user_data, free_windows_user_data, disconnected,
                 authenticated, send_credentials_pending, is_server, unused_bytes_recovered, allow_anonymous);
// STRUCT_PACK_DERIVED_DECL(DBusTransport, SerializableDBusTransport);

struct SerializableDBusWatch {
    int refcount; /**< Reference count. 用于跟踪 DBusWatch 对象的引用次数 */
    DBusPollable fd; /**< File descriptor. 被监视的文件描述符 */
    unsigned int flags; /**< Conditions to watch. 监视的条件，例如可读、可写等 */

    std::string handler; /**< Watch handler. 当文件描述符上发生事件时调用的处理函数 */
    std::string handler_data; /**< Watch handler data. 传递给处理函数的数据 */
    std::string free_handler_data_function; /**< Free the watch handler data. 释放处理函数数据的函数 */

    std::string data; /**< Application data. 应用程序特定的数据 */
    std::string free_data_function; /**< Free the application data. 释放应用程序数据的函数 */
    unsigned int enabled;
    unsigned int oom_last_time;
};
STRUCT_PACK_REFL(SerializableDBusWatch, refcount, fd, flags, handler, handler_data, free_handler_data_function, data,
                 free_data_function, enabled, oom_last_time);

struct SerializableDBusWatchList {
    std::vector<SerializableDBusWatch> watches;
    std::string add_watch_function; /**< Callback for adding a watch. */
    std::string remove_watch_function; /**< Callback for removing a watch. */
    std::string watch_toggled_function; /**< Callback on toggling enablement */
    std::string watch_data; /**< Data for watch callbacks */
    std::string watch_free_data_function; /**< Free function for watch callback data */
};
STRUCT_PACK_REFL(SerializableDBusWatchList, watches, add_watch_function, remove_watch_function, watch_toggled_function,
                 watch_data, watch_free_data_function);

struct SerializableDBusTimeout {
    int refcount; /**< Reference count */
    int interval; /**< Timeout interval in milliseconds. */

    std::string handler; /**< Timeout handler. */
    std::string handler_data; /**< Timeout handler data. */
    std::string free_handler_data_function; /**< Free the timeout handler data. */

    std::string data; /**< Application data. */
    std::string free_data_function; /**< Free the application data. */
    unsigned int enabled;
    unsigned int needs_restart;
};
STRUCT_PACK_REFL(SerializableDBusTimeout, refcount, interval, handler, handler_data, free_handler_data_function, data,
                 free_data_function, enabled, needs_restart);

struct SerializableDBusTimeoutList {
    std::vector<SerializableDBusTimeout> timeouts;

    std::string add_timeout_function; /**< Callback for adding a timeout. */
    std::string remove_timeout_function; /**< Callback for removing a timeout. */
    std::string timeout_toggled_function; /**< Callback when timeout is enabled/disabled or changes interval */
    std::string timeout_data; /**< Data for timeout callbacks */
    std::string timeout_free_data_function; /**< Free function for timeout callback data */
};
STRUCT_PACK_REFL(SerializableDBusTimeoutList, timeouts, add_timeout_function, remove_timeout_function,
                 timeout_toggled_function, timeout_data, timeout_free_data_function);

struct SerializableDBusMessageFilter {
    DBusAtomic refcount; /**< Reference count */
    std::string function; /**< Function to call to filter */
    std::string user_data; /**< User data for the function */
    std::string free_user_data_function; /**< Function to free the user data */
};
STRUCT_PACK_REFL(SerializableDBusMessageFilter, refcount, function, user_data, free_user_data_function);

struct SerialDBusConnection {
    DBusAtomic refcount; /**< Reference count. 用于管理 DBusConnection 对象的生命周期。 */

    std::vector<SerializableDBusMessage>
            outgoing_messages; /**< Queue of messages we need to send, send the end of the list first. 需要发送的消息队列，末尾的消息最先发送。 */
    std::vector<SerializableDBusMessage>
            incoming_messages; /**< Queue of messages we have received, end of the list received most recently. 已接收的消息队列，末尾的消息是最近接收的。 */

    std::vector<SerializableDBusMessage>
            expired_messages; /**< Messages that will be released when we next unlock. 下次解锁时释放的过期消息队列。 */

    SerializableDBusMessage message_borrowed; /**< Filled in if the first incoming message has been borrowed;
                                  *   dispatch_acquired will be set by the borrower
                                  *   如果第一个接收的消息被借用了，则该字段会被填充；借用者会设置 dispatch_acquired。
                                  */

    int n_outgoing; /**< Length of outgoing queue. 发送队列的长度。 */
    int n_incoming; /**< Length of incoming queue. 接收队列的长度。 */

    SerializableDBusCounter outgoing_counter; /**< Counts size of outgoing messages. 统计发送消息的大小。 */

    SerializableDBusTransport
            transport; /**< Object that sends/receives messages over network. 发送和接收网络消息的对象。 */
    SerializableDBusWatchList watches; /**< Stores active watches. 存储活跃的监视器列表。 */

    SerializableDBusTimeoutList timeouts; /**< Stores active timeouts. 存储活跃的超时列表。 */
    // 这个过滤器列表是什么时候被初始化的呢？
    std::vector<SerializableDBusMessageFilter> filter_list; /**< List of filters. 过滤器列表。 */

    std::vector<SerializableDBusDataSlot>
            slot_list; /**< Data stored by allocated integer ID 通过分配的整数 ID 存储的数据。 */

    // FIXME: 这样写是不对的，但是 DBusHashTable * pending_replies 这个hashtable暂时还不知道怎么保存
    std::string
            pending_replies; /**< Hash of message serials to #DBusPendingCall. 将消息序列号映射到 DBusPendingCall 的哈希表。 */
    // 用于存储当前等待回复的消息的哈希表,key是message的序列号,value是

    dbus_uint32_t
            client_serial; /**< Client serial. Increments each time a message is sent 客户端序列号，每次发送消息时递增。 */
    std::vector<SerializableDBusMessage>
            disconnect_message_link; /**< Preallocated list node for queueing the disconnection message 预分配的用于排队断开消息的列表节点。 */

    std::string wakeup_main_function; /**< Function to wake up the mainloop 唤醒主循环的函数。 */
    std::string wakeup_main_data; /**< Application data for wakeup_main_function 唤醒主循环函数的应用数据。 */
    std::string free_wakeup_main_data; /**< free wakeup_main_data 释放唤醒主循环数据的函数。 */

    std::string dispatch_status_function; /**< Function on dispatch status changes 调度状态更改时调用的函数。 */
    std::string dispatch_status_data; /**< Application data for dispatch_status_function 调度状态函数的应用数据。 */
    std::string free_dispatch_status_data; /**< free dispatch_status_data 释放调度状态数据的函数。 */

    DBusDispatchStatus
            last_dispatch_status; /**< The last dispatch status we reported to the application 上一次报告给应用程序的调度状态。 */

    // FIXME: 这个也不对，后面再改
    // DBusObjectTree
    //         *objects; /**< Object path handlers registered with this connection 在此连接中注册的对象路径处理程序。 */
    std::string objects;

    std::string
            server_guid; /**< GUID of server if we are in shared_connections, #NULL if server GUID is unknown or connection is private 如果在共享连接中，这是服务器的 GUID；如果服务器 GUID 未知或连接是私有的，则为 NULL。 */

    /* These two MUST be bools and not bitfields, because they are protected by a separate lock
   * from connection->mutex and all bitfields in a word have to be read/written together.
   * So you can't have a different lock for different bitfields in the same word.
   * 这两个必须是布尔值而不是位域，因为它们由与 connection->mutex 不同的锁保护，并且同一个字中的所有位域必须一起读/写。
   * 因此，您不能在同一个字中的不同位域上使用不同的锁。
   */
    dbus_bool_t
            dispatch_acquired; /**< Someone has dispatch path (can drain incoming queue) 表示是否有调度路径（可以处理接收队列中的消息）。 */
    dbus_bool_t
            io_path_acquired; /**< Someone has transport io path (can use the transport to read/write messages) 表示是否有传输 IO 路径（可以使用传输来读写消息）。 */

    unsigned int shareable;

    unsigned int exit_on_disconnect;

    unsigned int builtin_filters_enabled;

    unsigned int route_peer_messages;

    unsigned int disconnected_message_arrived;
    unsigned int disconnected_message_processed;

    unsigned int have_connection_lock;

    int generation; /**< _dbus_current_generation that should correspond to this connection 对应于当前连接的 _dbus_current_generation。 */
};
STRUCT_PACK_REFL(SerialDBusConnection, refcount, outgoing_messages, incoming_messages, expired_messages,
                 message_borrowed, n_outgoing, n_incoming, outgoing_counter, transport, watches, timeouts, filter_list,
                 slot_list, pending_replies, client_serial, disconnect_message_link, wakeup_main_function,
                 wakeup_main_data, free_wakeup_main_data, dispatch_status_function, dispatch_status_data,
                 free_dispatch_status_data, last_dispatch_status, objects, server_guid, dispatch_acquired,
                 io_path_acquired, shareable, exit_on_disconnect, builtin_filters_enabled, route_peer_messages,
                 disconnected_message_arrived, disconnected_message_processed, have_connection_lock, generation);

// void *serialize_dbus_connection(const DBusConnection *connection, size_t *size)
// {
//     SerialDBusConnection conn_serial;
//     conn_serial.refcount = dbus_connection_get_refcount(connection);
//
//     DBusList *outgoing_messages = dbus_connection_get_outgoing_messages(connection);
//     conn_serial.outgoing_messages = convert_message_list_to_vector(outgoing_messages);
//
//     DBusList *incoming_messages = dbus_connection_get_incoming_messages(connection);
//     conn_serial.incoming_messages = convert_message_list_to_vector(incoming_messages);
//
//     DBusList *expired_messages = dbus_connection_get_expired_messages(connection);
//     conn_serial.expired_messages = convert_message_list_to_vector(expired_messages);
//
//     DBusMessage *message_borrowed = dbus_connection_get_message_borrowed(connection);
//     conn_serial.message_borrowed = convert_message_to_message_serial(message_borrowed);
//
//     conn_serial.n_outgoing = dbus_connection_get_n_outgoing(connection);
//
//     conn_serial.n_incoming = dbus_connection_get_n_incoming(connection);
//
//     DBusTransport *transport = dbus_connection_get_transport(connection);
//     conn_serial.transport = convert_transport_to_transport_serial(transport);
//
//     DBusWatchList *watchers = dbus_connection_get_watch_list(connection);
//     conn_serial.watches = convert_watch_list_to_watch_list_serial(watchers);
//
//     DBusTimeoutList *timeouts = dbus_connection_get_timeout_list(connection);
//     conn_serial.timeouts = convert_timeout_list_to_timeout_list_serial(timeouts);
//
//     DBusList *filter_list = dbus_connection_get_filter_list(connection);
//     conn_serial.filter_list = convert_filter_list_to_vector(filter_list);
//
//     DBusDataSlotList slot_list = dbus_connection_get_slot_list(connection);
//     conn_serial.slot_list = convert_slot_list_to_vector(slot_list);
//
//     DBusHashTable *pending_replies = dbus_connection_get_pending_replies(connection);
//     conn_serial.pending_replies = convert_pending_replies_to_serial(pending_replies);
//
//     conn_serial.client_serial = dbus_connection_get_client_serial(connection);
//
//     DBusList *disconnect_message_link = dbus_connection_get_disconnect_message_link(connection);
//     conn_serial.disconnect_message_link = convert_disconnect_message_link_to_vector(disconnect_message_link);
//
//     //            std::string wakeup_main_function; /**< Function to wake up the mainloop 唤醒主循环的函数。 */
//     // DBusWakeupMainFunction wakeup_main_function; /**< Function to wake up the mainloop 唤醒主循环的函数。 */
//
//     // 序列化
//     std::vector<char> buffer = struct_pack::serialize(conn_serial);
//     *size = buffer.size();
//
//     // 分配内存并复制数据
//     void *result = malloc(*size);
//     std::memcpy(result, buffer.data(), *size);
//
//     return result;
// }

// DBusConnection *deserialize_dbus_connection(const void *data, size_t size)
// {
//     std::vector<char> buffer((char *)data, (char *)data + size);
//     auto result = struct_pack::deserialize<SerialDBusConnection>(buffer);
//
//     if (!result.has_value()) {
//         return nullptr;
//     }
//
//     DBusConnection *connection = (DBusConnection *)malloc(sizeof(DBusConnection));
//     connection->refcount.value = result->refcount.value;
//     connection->n_outgoing = result->n_outgoing;
//     connection->n_incoming = result->n_incoming;
//     // 根据SerialDBusConnection结构体填充其他字段
//
//     return connection;
// }
