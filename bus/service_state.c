#include "bus/service_state.h"
#include "dbus/dbus-macros.h"

static dbus_bool_t save_service_statue_to_file(service_state *state, char *file_path)
{
    return TRUE;
}

/**
 * @brief 将context的状态保存在文件中
 * 将conniption写入文件中，涉及到序列化
 *
 * @param service_name 指定的服务名称
 * @param file_path 保存服务状态的文件路径
 * @return 是否保存成功
 */
dbus_bool_t save_service_status(char *service_name, char *file_path, service_state *state)
{
    /* * 将conniption写入文件中，涉及到序列化
     */
    dbus_bool_t success = TRUE;
    success = save_service_statue_to_file(state, file_path);
    return success;
}
