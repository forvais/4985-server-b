#include "starter.h"
#include "args.h"
#include "io.h"
#include "messaging.h"
#include "networking.h"
#include "utils.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#define SLEEP 3         // 3s
#define TIMEOUT 3000    // 3s
#define INADDRESS "0.0.0.0"
#define OUTADDRESS "0.0.0.0"
#define PORT "8081"
#define SM_PORT "9000"
#define SM_HEADER_SIZE 4
#define BUF_SIZE 50

static const struct fsm_transition transitions[] = {
    {START,           CONNECT_SM,      connect_sm     },
    {CONNECT_SM,      PARSE_ENVP,      parse_envp     },
    {PARSE_ENVP,      WAIT_FOR_START,  wait_for_start },
    {WAIT_FOR_START,  LAUNCH_SERVER,   launch_server  },
    {LAUNCH_SERVER,   CLEANUP_HANDLER, cleanup_handler},
    {CLEANUP_HANDLER, END,             NULL           },
    {CONNECT_SM,      CLEANUP_HANDLER, cleanup_handler},
    {PARSE_ENVP,      CLEANUP_HANDLER, cleanup_handler},
    {WAIT_FOR_START,  CLEANUP_HANDLER, cleanup_handler},
};

fsm_state_t connect_sm(void *args)
{
    args_t *sm_args = (args_t *)args;
    while(running)
    {
        // Start TCP Client
        printf("Connecting to server manager...\n");
        *sm_args->sm_fd = tcp_client(sm_args->sm_addr, sm_args->sm_port, sm_args->err);
        printf("sm_fd: %d\n", *sm_args->sm_fd);
        if(*sm_args->sm_fd > 0)
        {
            printf("Connect to server manager at %s:%d\n", sm_args->sm_addr, sm_args->sm_port);
            return PARSE_ENVP;
        }
        perror("Failed to create TCP client.");
        errno         = 0;
        *sm_args->err = 0;
        sleep(SLEEP);
    }
    return CLEANUP_HANDLER;
}

fsm_state_t wait_for_start(void *args)
{
    struct pollfd fds[1];
    char          buf[SM_HEADER_SIZE];

    args_t *sm_args = (args_t *)args;
    memset(buf, 0, SM_HEADER_SIZE);

    fds[0].fd     = *sm_args->sm_fd;
    fds[0].events = POLLIN;

    while(running)
    {
        printf("polling\n");
        if(poll(fds, 1, -1) == -1)
        {
            perror("Poll error");
            return CLEANUP_HANDLER;
        }

        if(fds[0].revents & POLLIN)
        {
            printf("reading from sm\n");
            if(read_fully(fds[0].fd, buf, SM_HEADER_SIZE, sm_args->err) < 0)
            {
                perror("read_fully error");
                errno = 0;
                continue;
            }

            // print
            for(int i = 0; i < 4; i++)
            {
                printf("%d ", buf[i]);
            }
            printf("\n");

            if(buf[0] == SVR_Start)
            {
                printf("Server start requested %d\n", buf[0]);
                return LAUNCH_SERVER;
            }
        }
        if(fds[0].revents & (POLLHUP | POLLERR))
        {
            printf("sever manager exit\n");
            return CLEANUP_HANDLER;
        }
    }
    return CLEANUP_HANDLER;
}

extern char **environ;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables,-warnings-as-errors)

fsm_state_t parse_envp(void *args)
{
    const args_t *sm_args = (args_t *)args;
    char          buf[BUF_SIZE];
    char        **env = environ;

    setenv("ADDR", sm_args->addr, 1);

    snprintf(buf, BUF_SIZE, "%u", sm_args->port);
    setenv("PORT", buf, 1);
    memset(buf, 0, BUF_SIZE);

    setenv("SM_ADDR", sm_args->sm_addr, 1);

    snprintf(buf, BUF_SIZE, "%u", sm_args->sm_port);
    setenv("SM_PORT", buf, 1);
    memset(buf, 0, BUF_SIZE);

    snprintf(buf, BUF_SIZE, "%d", *sm_args->sm_fd);
    setenv("SM_FD", buf, 1);
    memset(buf, 0, BUF_SIZE);

    while(*env)
    {
        printf("%s\n", *env);
        env++;
    }

    return WAIT_FOR_START;
}

fsm_state_t launch_server(void *args)
{
    int           status;
    pid_t         pid;
    char          buf[SM_HEADER_SIZE];
    struct pollfd fds[1];

    args_t *sm_args = (args_t *)args;
    memset(buf, 0, SM_HEADER_SIZE);

    pid = fork();

    if(pid < 0)
    {
        perror("main::fork");
        return CLEANUP_HANDLER;
    }

    if(pid == 0)
    {
        execv("./build/server", NULL);

        // _exit if fails
        perror("execv failed");
        _exit(EXIT_FAILURE);
    }

    fds[0].fd     = *sm_args->sm_fd;
    fds[0].events = POLLIN;

    while(running)
    {
        ssize_t result;

        errno = 0;
        printf("polling...\n");
        result = poll(fds, 1, TIMEOUT);
        if(result == -1)
        {
            perror("Poll error");
            return CLEANUP_HANDLER;
        }
        if(result == 0)
        {
            printf("check child\n");
            if(waitpid(pid, &status, WNOHANG) > 0)
            {
                printf("Child exited, status = %d\n", WEXITSTATUS(status));
                return CLEANUP_HANDLER;
            }
        }
        if(fds[0].revents & POLLIN)
        {
            if(read_fully(fds[0].fd, buf, SM_HEADER_SIZE, sm_args->err) < 0)
            {
                perror("read_fully error");
                errno = 0;
                continue;
            }
            printf("Received byte: %d\n", buf[0]);
            if(buf[0] == SVR_Stop)
            {
                printf("Killing child process...\n");
                kill(pid, SIGINT);
                waitpid(pid, &status, 0);    // Ensure child cleanup
                return CLEANUP_HANDLER;
            }
        }
        if(fds[0].revents & (POLLHUP | POLLERR))
        {
            printf("server manager exit\n");
            printf("Killing child process...\n");
            kill(pid, SIGINT);
            waitpid(pid, &status, 0);    // Ensure child cleanup
            return CLEANUP_HANDLER;
        }
    }
    kill(pid, SIGINT);
    waitpid(pid, &status, 0);    // Ensure child cleanup
    return CLEANUP_HANDLER;
}

fsm_state_t cleanup_handler(void *args)
{
    const args_t *sm_args = (args_t *)args;

    close(*sm_args->sm_fd);
    return END;
}

int main(int argc, char *argv[])
{
    int            err;
    args_t         args;
    int            sm_fd;
    fsm_state_func perform;
    fsm_state_t    from_id;
    fsm_state_t    to_id;

    setup_signal();

    printf("Starter launching... (press Ctrl+C to interrupt)\n");

    err = 0;
    memset(&args, 0, sizeof(args_t));
    args.addr = INADDRESS;
    convert_port(PORT, &args.port);
    args.sm_addr = OUTADDRESS;
    convert_port(SM_PORT, &args.sm_port);
    args.sm_fd = &sm_fd;
    args.err   = &err;

    get_arguments(&args, argc, argv);

    from_id = START;
    to_id   = CONNECT_SM;

    do
    {
        perform = fsm_transition(from_id, to_id, transitions, sizeof(transitions));
        if(perform == NULL)
        {
            printf("illegal state %d, %d \n", from_id, to_id);
            close(sm_fd);
            break;
        }
        // printf("from_id %d\n", from_id);
        from_id = to_id;
        to_id   = perform(&args);
    } while(to_id != END);
}
