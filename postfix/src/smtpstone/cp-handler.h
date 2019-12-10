#include <sys/types.h>
#include <sys/socket.h>

typedef void(*ACCEPT_NOTIFY_FN)(int,struct sockaddr* addr,int len);

void init_child_processes(int num_process,ACCEPT_NOTIFY_FN fn);

int ask_child_to_connect(int fd, struct sockaddr *addr,int len);