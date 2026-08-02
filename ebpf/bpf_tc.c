#include "ebpf/multihop.h"

#define CONTAINER_LABEL 1
#define CONTAINER_NAME "HOST"

int tc_ingress(struct __sk_buff *skb) {
    u64 start = bpf_ktime_get_ns();
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr eth_copy;
    struct iphdr iph_copy;
    struct tcphdr tcph_copy;
    multihop_state st_copy;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(struct ethhdr) > data_end)
    { 
        return TC_ACT_OK;
    }

    // Check if the packet is IP
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    { 
        return TC_ACT_OK;
    }

    // Parse IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
    { 
        return TC_ACT_OK;
    }

    if (ip->protocol != IP_TCP)
    { 
        return TC_ACT_OK;
    }
    
    // Parse TCP header
    struct tcphdr *tcph = (struct tcphdr *)(ip + 1);
    if ((void *)tcph + sizeof(struct tcphdr) > data_end)
    { 
        return TC_ACT_OK;
    }

    if (!tcph->syn || tcph->ack)
    { 
        return TC_ACT_OK;
    }
    multihop_state *st = (multihop_state *)(tcph + 1);
    if ((void *)st + sizeof(multihop_state) > data_end)
    { 
        return TC_ACT_OK;
    }
    if (bpf_skb_load_bytes(skb, 0, &eth_copy, sizeof(struct ethhdr)))
    { 
        return TC_ACT_OK;
    }

    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &iph_copy, sizeof(struct iphdr)))
    { 
        return TC_ACT_OK;
    }

    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &tcph_copy, sizeof(struct tcphdr)))
    { 
        return TC_ACT_OK;
    }

    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), &st_copy, sizeof(multihop_state)))
    { 
        return TC_ACT_OK;
    }

    // if (bpf_skb_adjust_room(skb, - (int) sizeof(multihop_state), BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO))
    // { 
    //     return TC_ACT_OK;
    // }

    if (bpf_skb_store_bytes(skb, 0, &eth_copy, sizeof(struct ethhdr), 0))
    { 
        return TC_ACT_OK;
    }
    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &iph_copy, sizeof(struct iphdr), 0))
    { 
        return TC_ACT_OK;
    }
    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &tcph_copy, sizeof(struct tcphdr), 0))
    { 
        return TC_ACT_OK;
    }

    struct multihop_map_key k = {.st = st_copy, .t = CONTAINER_LABEL};
    multihop_state * next_state_lookup = access_control.lookup(&k);
    multihop_state next_state = 0;
    if (!next_state_lookup)
    {
        // bpf_trace_printk("[" CONTAINER_NAME "] Rejecting Packet with state %d transition %d", st_copy, CONTAINER_LABEL);
        // return TC_ACT_OK;
        next_state = 0;
    }else {
        next_state = *next_state_lookup;
        // bpf_trace_printk("[" CONTAINER_NAME "] Accepting Packet with state %d, next state %d", st_copy, next_state);
    }
    struct four_tuple ft = {};
    ft.saddr = bpf_ntohl(iph_copy.saddr);
    ft.daddr = bpf_ntohl(iph_copy.daddr);
    ft.sport = bpf_ntohs(tcph_copy.source);
    ft.dport = bpf_ntohs(tcph_copy.dest);
    conn_to_state_ingress.update(&ft, &next_state);
    u64 end = bpf_ktime_get_ns();
    u64 delta = end - start;
    // bpf_trace_printk("[" CONTAINER_NAME "] TC Ingress took %llu ns", delta);

    return TC_ACT_OK;
}

int tc_egress(struct __sk_buff *skb) {
    u64 start = bpf_ktime_get_ns();
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr eth_copy;
    struct iphdr iph_copy;
    struct tcphdr tcph_copy;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(struct ethhdr) > data_end)
    { 
        return TC_ACT_OK;
    }

    // Check if the packet is IP
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    { 
        return TC_ACT_OK;
    }

    // Parse IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
    { 
        return TC_ACT_OK;
    }

    if (ip->protocol != IP_TCP)
    { 
        return TC_ACT_OK;
    }
    
    // Parse TCP header
    struct tcphdr *tcph = (struct tcphdr *)(ip + 1);
    if ((void *)tcph + sizeof(struct tcphdr) > data_end)
    { 
        return TC_ACT_OK;
    }

    if (!tcph->syn || tcph->ack)
    { 
        return TC_ACT_OK;
    }

    if (bpf_skb_load_bytes(skb, 0, &eth_copy, sizeof(eth_copy)))
    { 
        return TC_ACT_OK;
    }

    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &iph_copy, sizeof(iph_copy)))
    { 
        return TC_ACT_OK;
    }

    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &tcph_copy, sizeof(tcph_copy)))
    { 
        return TC_ACT_OK;
    }

    struct four_tuple ft = {};
    ft.saddr = bpf_ntohl(iph_copy.saddr);
    ft.daddr = bpf_ntohl(iph_copy.daddr);
    ft.sport = bpf_ntohs(tcph_copy.source);
    ft.dport = bpf_ntohs(tcph_copy.dest);

    multihop_state state=0;
    multihop_state * state_lookup = conn_to_state_egress.lookup(&ft);
    if ( state_lookup )
    {
        state = *state_lookup;
    } else
    {
        // This is the first hop
        struct multihop_map_key k = {.st = 0, .t = CONTAINER_LABEL};
        multihop_state * fh_st_lookup = access_control.lookup(&k);
        if (fh_st_lookup) 
        {
            state = *fh_st_lookup;
        } else {
            // bpf_trace_printk("[" CONTAINER_NAME "] Can't initiate connection, transition %d start state 0", CONTAINER_LABEL);
            // return TC_ACT_OK;
            state = 0;
        }
    }
    // bpf_trace_printk("[" CONTAINER_NAME "] Initiate Packet with state %d", state);
    if (bpf_skb_adjust_room(skb, sizeof(state), BPF_ADJ_ROOM_MAC, 0))
    { 
        return TC_ACT_OK;
    }
    if (bpf_skb_store_bytes(skb, 0, &eth_copy, sizeof(eth_copy), 0))
    { 
        return TC_ACT_OK;
    }

    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &iph_copy, sizeof(iph_copy), 0))
    { 
        return TC_ACT_OK;
    }

    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &tcph_copy, sizeof(tcph_copy), 0))
    { 
        return TC_ACT_OK;
    }

    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), &state, sizeof(state), 0))
    { 
        return TC_ACT_OK;
    }
    u64 end = bpf_ktime_get_ns();
    u64 delta = end - start;
    // bpf_trace_printk("[" CONTAINER_NAME "] TC Egress took %llu ns", delta);
    return TC_ACT_OK;
}