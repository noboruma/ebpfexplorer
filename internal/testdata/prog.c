// A small XDP program for the code view tests:
// clang -O2 -g -target bpf -c prog.c -o prog.o
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))

struct xdp_md {
	__u32 data, data_end, data_meta, ingress_ifindex, rx_queue_index, egress_ifindex;
};

struct {
	int (*type)[1];  // BPF_MAP_TYPE_HASH
	int (*max_entries)[1024];
	__u32 *key;
	__u64 *value;
} counts SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;

static __attribute__((noinline)) __u32 bucket(__u32 len)
{
	return len >> 6;
}

SEC("xdp")
int count_packets(struct xdp_md *ctx)
{
	__u32 key = bucket(ctx->data_end - ctx->data);
	__u64 one = 1, *n = bpf_map_lookup_elem(&counts, &key);
	if (n) {
		__sync_fetch_and_add(n, 1);
		return 2; // XDP_PASS
	}
	bpf_map_update_elem(&counts, &key, &one, 0);
	return 2;
}

char LICENSE[] SEC("license") = "GPL";
