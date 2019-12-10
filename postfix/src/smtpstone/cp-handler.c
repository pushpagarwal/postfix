#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <mymalloc.h>
#include <iostuff.h>
#include <events.h>
#include <signal.h>
#include <sys/wait.h>

#include <stdio.h>

#include "cp-handler.h"


extern void msg_panic(const char *,...);

#define HAVE_MSGHDR_MSG_CONTROL 1

static ssize_t recv_fd(int fd, void *ptr, size_t nbytes, int *recvfd)
 {
     struct msghdr msg;
     struct iovec iov[1];
     ssize_t n;

 #ifdef HAVE_MSGHDR_MSG_CONTROL
     union {
         struct cmsghdr cm;
         char     control[CMSG_SPACE(sizeof (int))];
     } control_un;
     struct cmsghdr  *cmptr;

     msg.msg_control  = control_un.control;
     msg.msg_controllen = sizeof(control_un.control);
 #else
     int     newfd;

     msg.msg_accrights = (caddr_t) & newfd;
     msg.msg_accrightslen = sizeof(int);
 #endif

     msg.msg_name = 0;
     msg.msg_namelen = 0;

     iov[0].iov_base = ptr;
     iov[0].iov_len = nbytes;
     msg.msg_iov = iov;
     msg.msg_iovlen = 1;

     if ( (n = recvmsg(fd, &msg, 0)) <= 0)
         return (n);

 #ifdef  HAVE_MSGHDR_MSG_CONTROL
     if ( (cmptr = CMSG_FIRSTHDR(&msg)) != 0 &&
         cmptr->cmsg_len == CMSG_LEN(sizeof(int))) {
         if (cmptr->cmsg_level != SOL_SOCKET)
             msg_panic("control level != SOL_SOCKET");
         if (cmptr->cmsg_type != SCM_RIGHTS)
             msg_panic("control type != SCM_RIGHTS");
         *recvfd = *((int *) CMSG_DATA(cmptr));
     } else
         *recvfd = -1;           /* descriptor was not passed */
 #else
     if (msg.msg_accrightslen == sizeof(int))
         *recvfd = newfd;
     else
         *recvfd = -1;       /* descriptor was not passed */
 #endif

     return (n);
 }


static ssize_t send_fd(int fd, void *ptr, size_t nbytes, int sendfd)
{
    struct msghdr msg;
    struct iovec iov[1];

#ifdef  HAVE_MSGHDR_MSG_CONTROL
    union {
        struct cmsghdr cm;
         char    control[CMSG_SPACE(sizeof(int))];
     } control_un;
     struct cmsghdr *cmptr;

     msg.msg_control = control_un.control;
     msg.msg_controllen = sizeof(control_un.control);

     cmptr = CMSG_FIRSTHDR(&msg);
     cmptr->cmsg_len = CMSG_LEN(sizeof(int));
     cmptr->cmsg_level = SOL_SOCKET;
     cmptr->cmsg_type = SCM_RIGHTS;
     *((int *) CMSG_DATA(cmptr)) = sendfd;
 #else
     msg.msg_accrights = (caddr_t) & sendfd;
     msg.msg_accrightslen = sizeof(int);
 #endif

     msg.msg_name = 0;
     msg.msg_namelen = 0;

     iov[0].iov_base = ptr;
     iov[0].iov_len = nbytes;
     msg.msg_iov = iov;
     msg.msg_iovlen = 1;

     return (sendmsg(fd, &msg, 0));
 }
 
 typedef struct child_process_info_t 
 {
	 pid_t pid;
	 int fd;
 } child_process_info_t;
 
 static child_process_info_t* child_processes = 0;
static int max_child_processes;
static int number_of_child_processes =0;
static int round_robin_process=0;
 
  
static ACCEPT_NOTIFY_FN on_child_connect; 

 
static void set_process_info(int index, pid_t pid, int fd)
{
	child_processes[index].pid = pid;
	child_processes[index].fd = fd;
}

#define MSG_SEND_FD 1

typedef struct msg_send_fd
{
	int type;
	int parent_fd;
	int sa_len;
	struct sockaddr ss;
}msg_send_fd;

static void read_from_parent(int unused_event, void *context)
{
	char buff[1024];
	int n= 0;
	int fd = (int)context;
	int newfd=0;
	if((n = recv_fd(fd,buff,1024,&newfd))<0)
		return;
	if(n!=sizeof(msg_send_fd))
		return;
	msg_send_fd* msg = (msg_send_fd*)buff;
	
	if(msg->type != MSG_SEND_FD)
		return;
	non_blocking(newfd, NON_BLOCKING);
	on_child_connect(newfd,&(msg->ss),msg->sa_len);
}




int ask_child_to_connect(int fd, struct sockaddr*sa, int len){
	if(number_of_child_processes == 0)
	{
		on_child_connect(fd,sa,len);
		return;
	}
	struct msg_send_fd msg;
	memset(&msg,0,sizeof(msg));
	msg.type = MSG_SEND_FD;
	msg.sa_len = len;
	memcpy(&msg.ss,sa,sizeof(*sa));
	int n = send_fd(child_processes[round_robin_process].fd,&msg,sizeof(msg),fd);
	close(fd);
	round_robin_process =(round_robin_process+1)%number_of_child_processes;
	return n;
}
static void init_child_process(int fd)
{
	non_blocking(fd, NON_BLOCKING);
	event_enable_read(fd, read_from_parent,(void*)fd);
	for (;;)
		event_loop(-1);
}
 
 static int create_child_process(int process_index)
 {
    int     sockfd[2];
    pid_t   childpid;
    socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfd); 	 
    childpid = fork();
    if (childpid == 0) { /* 2.1 if fork returned zero, you are the child */
        close(sockfd[0]); /* Close the parent file descriptor */
        init_child_process(sockfd[1]);
    } else { /* 2.2 ... you are the parent */
        close(sockfd[1]); /* Close the child file descriptor */
        set_process_info(process_index,childpid,sockfd[0]);
    }
    return childpid;
 }
 
 static void unregister_child(pid_t pid)
{
	int i=0;
	for(i =0; i< number_of_child_processes;++i)
	{
		if(child_processes[i].pid == pid)
			break;
	}
	if(i<number_of_child_processes)
		--number_of_child_processes;
	for(;i<number_of_child_processes;++i)
	{
		child_processes[i] = child_processes[i+1];
	}
	round_robin_process =0;
}
static void sig_chld_handler(int signum)
{
    pid_t pid;
    int   status;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
    {
        unregister_child(pid);   
	 printf("Child process %d quit with status:%d\n", pid, status);   
    }
}
void init_child_processes(int num_process,ACCEPT_NOTIFY_FN fn)
 {
	 on_child_connect = fn;
	 max_child_processes = num_process;
	if(!child_processes)
		child_processes = (child_process_info_t*) mymalloc(max_child_processes*sizeof(child_process_info_t));
	 for(; number_of_child_processes < max_child_processes; ++number_of_child_processes)
		create_child_process(number_of_child_processes);
	signal(SIGCHLD,sig_chld_handler);
}
