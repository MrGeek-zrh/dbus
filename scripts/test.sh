#!/bin/bash
set -xe
# 检查是否提供了操作参数
if [ -z "$1" ]; then
	echo "Usage: $0 [c|r|cl|rl]"
	echo "c: checkpoint"
	echo "r: restore"
	echo "cl: view the checkpoint log"
	echo "rl: view the restore log"
	exit 1
fi
# 设置 CRIU 存储路径
dump_path="/tmp/criu/service"
inode_file="$dump_path/inode.txt"
mkdir -p $dump_path
touch $inode_file
checkpoint_log="$dump_path/dump.log"
restore_log="$dump_path/restore.log"
# 执行 checkpoint 操作
if [ "$1" == "c" ]; then
	# 获取进程 ID
	pid=$(pgrep system_service)
	# 检查是否找到进程
	if [ -z "$pid" ]; then
		echo "Error: system_service process not found."
		exit 1
	fi
	echo "Found system_service process with PID: $pid"
	# 提取 Unix 套接字的 inode 编号
	socket_info=$(sudo lsof -p $pid | grep unix | grep STREAM)
	if [ -z "$socket_info" ]; then
		echo "Error: No Unix socket found for system_service."
		exit 1
	fi
	# 提取 inode 编号
	inode=$(echo "$socket_info" | awk '{print $8}')
	if [ -z "$inode" ]; then
		echo "Error: Unable to extract inode from socket info."
		exit 1
	fi
	echo "Found Unix socket inode: $inode"
	# 存储 inode 编号以便恢复时使用
	echo "$inode" >"$inode_file"
	# 创建存储路径
	mkdir -p $dump_path
	# 执行 checkpoint
	echo "Starting checkpoint..."
	sudo criu dump -t $pid -v4 --shell-job --tcp-established \
		--ext-unix-sk --file-locks --link-remap --force-irmap \
		--manage-cgroups --enable-external-sharing --enable-external-masters \
		-D $dump_path -o $checkpoint_log \
		--external unix[$inode]
	# 检查 checkpoint 是否成功
	if [ $? -ne 0 ]; then
		echo "Error: Checkpoint failed."
		exit 1
	fi
	echo "Checkpoint completed successfully."
# 执行 restore 操作
elif [ "$1" == "r" ]; then
	# 检查 inode 文件是否存在
	if [ ! -f "$inode_file" ]; then
		echo "Error: Inode file not found. Please run checkpoint first."
		exit 1
	fi
	# 读取 inode 编号
	inodes=$(cat "$inode_file")

	# 获取 D-Bus 系统总线 socket 的 inode
	dbus_inode=$(sudo ls -i /run/dbus/system_bus_socket | awk '{print $1}')

	# 构建 --external 参数
	external_params=""
	for inode in $inodes $dbus_inode; do
		external_params="$external_params --external unix[$inode]:/run/dbus/system_bus_socket"
	done

	# 执行恢复
	echo "Starting restore..."
	sudo criu restore -d -v4 --shell-job --tcp-established \
		--ext-unix-sk --file-locks --link-remap --force-irmap \
		--manage-cgroups --enable-external-sharing --enable-external-masters \
		--auto-dedup -D $dump_path -o $restore_log \
		$external_params

	# 检查恢复是否成功
	if [ $? -ne 0 ]; then
		echo "Error: Restore failed."
		echo "Displaying restore log for debugging:"
		cat "$restore_log"
		exit 1
	fi
	echo "Restore completed successfully."
	# 验证恢复结果
	new_pid=$(pgrep system_service)
	if [ -z "$new_pid" ]; then
		echo "Error: system_service process not found after restore."
		exit 1
	fi
	echo "system_service successfully restored with PID: $new_pid"
# 查看 checkpoint 日志
elif [ "$1" == "cl" ]; then
	if [ ! -f "$checkpoint_log" ]; then
		echo "Error: Checkpoint log not found."
		exit 1
	fi
	echo "Displaying checkpoint log:"
	batcat "$checkpoint_log"
# 查看 restore 日志
elif [ "$1" == "rl" ]; then
	if [ ! -f "$restore_log" ]; then
		echo "Error: Restore log not found."
		exit 1
	fi
	echo "Displaying restore log:"
	batcat "$restore_log"
else
	echo "Invalid option: $1"
	echo "Usage: $0 [c|r|cl|rl]"
	echo "c: checkpoint"
	echo "r: restore"
	echo "cl: view the checkpoint log"
	echo "rl: view the restore log"
	exit 1
fi
