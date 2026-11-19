#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

static volatile sig_atomic_t stopping = 0;
static void stop(int signal) { stopping = signal; }

int main(int argc, char **argv) {
    if (argc < 4 || strcmp(argv[1], "--parent")) return 2;
    pid_t parent = (pid_t)strtol(argv[2], NULL, 10);
    int session = strcmp(argv[3], "--session-channel") == 0;
    int tool = session ? 4 : 3;
    if (tool >= argc) return 2;
    if (parent <= 1 || getppid() != parent || argv[tool][0] != '/') return 2;
    umask(0077);
    struct sigaction action = {0}; action.sa_handler = stop; sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL); sigaction(SIGINT, &action, NULL); sigaction(SIGHUP, &action, NULL);
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        setpgid(0, 0);
        signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL); signal(SIGHUP, SIG_DFL);
        // Foundation passes the socket as stdin and the read/write PTY as stdout.
        // Move the socket to fd 3 and restore interactive stdin before exec.
        if (session && (dup2(STDIN_FILENO, 3) < 0 || dup2(STDOUT_FILENO, STDIN_FILENO) < 0)) _exit(126);
        execv(argv[tool], &argv[tool]); perror("启动工具失败"); _exit(127);
    }
    if (session) close(STDIN_FILENO);
    setpgid(child, child);
    int status = 0, ticks = 0;
    while (1) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) break;
        if (result < 0 && errno != EINTR) return 1;
        if (getppid() != parent || kill(parent, 0) != 0) stopping = SIGTERM;
        if (stopping) {
            kill(-child, ticks++ < 20 ? SIGTERM : SIGKILL);
        }
        usleep(100000);
    }
    kill(-child, SIGTERM);
    if (stopping) return 130;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
