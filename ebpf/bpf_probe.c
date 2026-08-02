#include "ebpf/multihop.h"
#include <net/sock.h>

int kretprobe_inet_csk_accept(struct pt_regs *ctx){
    u64 start = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk) return 0;
    struct four_tuple ft = {};
    ft.saddr = bpf_ntohl(sk->__sk_common.skc_daddr);
    ft.daddr = bpf_ntohl(sk->__sk_common.skc_rcv_saddr);
    ft.sport = bpf_ntohs(sk->__sk_common.skc_dport);
    ft.dport = sk->__sk_common.skc_num;
    multihop_state * st = conn_to_state_ingress.lookup(&ft);
    if (st) 
    {
        pid_to_state.update(&pid, st);
    }
    u64 end = bpf_ktime_get_ns();
    u64 delta = end - start;
    // bpf_trace_printk("kretprobe_inet_csk_accept took %llu ns", delta);
    return 0;
}

int kprobe_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
    u64 start = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    multihop_state * st = pid_to_state.lookup(&pid);
    if (!st) return 0;
	// pull in details
    struct four_tuple ft = {};
	ft.saddr = (u32) bpf_ntohl(sk->__sk_common.skc_rcv_saddr);
	ft.daddr = (u32) bpf_ntohl(sk->__sk_common.skc_daddr);
	ft.dport = (u16) bpf_ntohs(sk->__sk_common.skc_dport);
    ft.sport = (u16) sk->__sk_common.skc_num;

    conn_to_state_egress.update(&ft, st);
    u64 end = bpf_ktime_get_ns();
    u64 delta = end - start;
    // bpf_trace_printk("kretprobe_tcp_connect took %llu ns", delta);
	return 0;
}

int syscall_clone (struct pt_regs *ctx, unsigned long flags, void *child_stack,
                void *ptid, void *ctid, struct pt_regs *regs) 
{
    u64 start = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 child_pid = PT_REGS_RC(ctx);
    if (child_pid <= 0) 
    {
        return 1;
    }
    multihop_state * st = pid_to_state.lookup(&pid);
    if(st)
    {
        pid_to_state.update(&child_pid, st);
    } 
    else 
    {
        multihop_state s = 0;
        pid_to_state.update(&child_pid, &s);
    }

    u64 end = bpf_ktime_get_ns();
    u64 delta = end - start;
    // bpf_trace_printk("syscall_clone took %llu ns", delta);

    return 0;
}