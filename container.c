#define _GNU_SOURCE

#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdio.h>
#include <fcntl.h>

#define SYSROOT_DIR "/home/minicamp/sysroot-debian-bullseye"
#define INIT_PATH "/bin/init"
#define STACK_SIZE (16 * 1024 * 1024)
#define STR_BUF_SIZE 1024
int chroot_dir(const char *const path)
{
  if (chroot(path) != 0)
    return -1;
  if (chdir("/") != 0)
    return -1;
  return 0;
}

typedef struct
{
  int fd[2];
} isolated_child_args_t;

int isolated_child(isolated_child_args_t *args)
{
  char buf[1];
  if (read(args->fd[0], buf, 1) == -1)
    return -1;
  if (chroot_dir(SYSROOT_DIR) == -1)
    return -1;
  if (child_install_network() == -1)
    return -1;
  char *const init_arg[] = {INIT_PATH, NULL};
  char *const init_env[] = {NULL};
  //pertmisson errer mount: /proc: permission denied.
  //mount: /sys: permission denied.
  execve(INIT_PATH, init_arg, init_env);
  return -1;
}

#define SHELL_PATH "/bin/bash"
int exec_command_child(char *cmd)
{
  char *const argv[] = {SHELL_PATH, "-c", cmd, NULL}, *const envp[] = {NULL};
  execve(SHELL_PATH, argv, envp);
  return -1;
}

int exec_command(const char *const cmd)
{
  char *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_STACK, -1, 0);
  if (stack == MAP_FAILED)
    return -1;
  pid_t child = clone((int (*)(void *))exec_command_child, stack + STACK_SIZE, SIGCHLD, cmd);
  if (child == -1)
    return -1;
  if (waitpid(child, NULL, 0) == -1)
    return -1;
  return 0;
}

int parent_install_network(pid_t child)
{
  exec_command("ip link add vethA type veth peer vethB");
  exec_command("ip link set dev vethA up");
  exec_command("ip address add 10.0.0.1/24 dev vethA");
  char cmd[STR_BUF_SIZE];
  snprintf(cmd, STR_BUF_SIZE, "ip link set dev vethB netns %d", child);
  exec_command(cmd);
  exec_command("iptables --table nat --append POSTROUTING --source 10.0.0.0/24 --out-interface ens4 --jump MASQUERADE");
  exec_command("iptables --table filter --append FORWARD --source 10.0.0.0/24 --jump ACCEPT");
  exec_command("iptables --table filter --append FORWARD --destination 10.0.0.0/24 --match conntrack --ctstate ESTABLISHED,RELATED --jump ACCEPT");
}
int child_install_network()
{
  exec_command("ip link set dev vethB up");
  exec_command("ip address add 10.0.0.2/24 dev vethB");
  exec_command("ip route add default via 10.0.0.1");
}

int parent_uninstall_network(pid_t child)
{
  exec_command("ip link delete vethA");
}
int write_file(const char *const path, const char *const str)
{
  int fd = open(path, O_WRONLY), len;
  if (fd == -1)
    return -1;
  for (len = 0; str[len] != '\0'; len++)
    ;
  if (write(fd, str, len) != len)
    return -1;
  if (close(fd) == -1)
    return -1;
  return 0;
}
int parent_write_ug_map(pid_t child)
{
  char path[STR_BUF_SIZE], data[STR_BUF_SIZE];
  snprintf(path, STR_BUF_SIZE, "/proc/%d/setgroups", child);
  if (write_file(path, "deny") == -1)
    return -1;
  snprintf(path, STR_BUF_SIZE, "/proc/%d/gid_map", child);
  snprintf(data, STR_BUF_SIZE, "0 %d 1\n", getgid());
  if (write_file(path, data) == -1)
    return -1;
  snprintf(path, STR_BUF_SIZE, "/proc/%d/uid_map", child);
  snprintf(data, STR_BUF_SIZE, "0 %d 1\n", getuid());
  if (write_file(path, data) == -1)
    return -1;
  return 0;
}

int start_child()
{
  isolated_child_args_t args;
  if (pipe(args.fd) == -1)
    return -1;
  char *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_STACK, -1, 0);
  if (stack == MAP_FAILED)
    return -1;
  pid_t child = clone((int (*)(void *))isolated_child, stack + STACK_SIZE,
                      SIGCHLD | CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWNET, &args);
  if (child == -1)
    return -1;
  if (parent_write_ug_map(child) == -1)
    return -1;
  if (parent_install_network(child) == -1)
    return -1;
  if (write(args.fd[1], "\0", 1) == -1)
    return -1;
  if (waitpid(child, NULL, 0) == -1)
    return -1;
  if (parent_uninstall_network(child) == -1)
    return -1;
  return 0;
}

int main()
{

  return start_child();
}
//CLONE_NEWUSER|CLONE_NEWNS
