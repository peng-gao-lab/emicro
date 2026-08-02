#include <uapi/linux/bpf.h>         // core BPF types and __sk_buff
#include <uapi/linux/if_ether.h>    // Ethernet header (struct ethhdr)
#include <uapi/linux/ip.h>          // IPv4 header (struct iphdr)
#include <uapi/linux/tcp.h>         // TCP header (struct tcphdr)
#include <uapi/linux/pkt_cls.h>     // TC filter definitions

#define IP_TCP 6

typedef u32 multihop_state;
typedef u32 transition;
typedef multihop_state multihop_map_entry; 

struct four_tuple 
{
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
} __attribute__((packed));

struct multihop_map_key 
{
    multihop_state st;
    transition t;
};

BPF_TABLE_PINNED("hash", struct four_tuple, multihop_state, conn_to_state_ingress, 1024, "/sys/fs/bpf/conn_to_state_ingress"); //map socket identifier to multihop state
BPF_TABLE_PINNED("hash", struct four_tuple, multihop_state, conn_to_state_egress, 1024, "/sys/fs/bpf/conn_to_state_egress"); //map socket identifier to multihop state
BPF_TABLE_PINNED("hash", u32, multihop_state, pid_to_state, 1024, "/sys/fs/bpf/pid_to_state"); //map pid to multihop state
BPF_TABLE_PINNED("hash", struct multihop_map_key, multihop_map_entry, access_control, 1024, "/sys/fs/bpf/access_control"); //map pid to multihop state with transition