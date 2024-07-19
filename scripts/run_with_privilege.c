#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    // 执行传递的命令
    execvp(argv[1], &argv[1]);

    // 如果 execvp 失败，输出错误并返回
    perror("execvp");
    return 1;
}
