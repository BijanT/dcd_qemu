#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPH_MEM_DONATION_GRANULARITY ((__s64)256 * 1024 * 1024)
#define MAX_CAS_LOOPS 100

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/*
 * Declare bpf_fault types here instead of getting them from vmlinux.h to allow
 * building this on a machine without the bpf_fault kernel.
 */
struct bpf_fault_ops_ctx;
struct fault_ops {
    int (*handle_page_fault)(struct bpf_fault_ops_ctx *ctx, unsigned char *buf);
    int (*handle_wp_fault)(struct bpf_fault_ops_ctx *ctx, unsigned char *buf);
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    /* 1MB might be too large, but better to be too big than too small */
    __uint(max_entries, 1024 * 1024);
} revoke_event_rb SEC(".maps");

struct ephemeral_state {
    __u64 size_to_revoke;
};

const __u64 backend_size = 0;
volatile __u64 donated_size = 0;
volatile __u64 revoked_size = 0;
volatile __u64 faulted_size = 0;

/* Atomically updates the revoked size if running low on memory */
static long revoke_cas_loop(__u32 index, void *ctx)
{
    struct ephemeral_state *state = ctx;
    __u64 old_revoked_size = revoked_size;
    __u64 new_revoked_size;
    __u64 local_donated_size = donated_size;
    __u64 local_faulted_size = faulted_size;
    __u64 size_to_revoke;
    __u64 used_size;
    __s64 headroom;
    __u64 cas_ret;

    used_size = local_donated_size + local_faulted_size;
    headroom = backend_size + old_revoked_size - used_size;
    size_to_revoke = MIN(EPH_MEM_DONATION_GRANULARITY,
        local_donated_size - old_revoked_size);

    /* Plenty of room. No need to revoke. */
    if (headroom > EPH_MEM_DONATION_GRANULARITY) {
        return 1;
    }

    /* If there's nothing to revoke, don't do anything */
    if (size_to_revoke == 0) {
        return 1;
    }

    /* Attempt to revoke memory. */
    new_revoked_size = old_revoked_size + size_to_revoke;

    cas_ret = __sync_val_compare_and_swap(&revoked_size, old_revoked_size,
        new_revoked_size);
    if (cas_ret == old_revoked_size) {
        state->size_to_revoke = size_to_revoke;
        return 1;
    }

    return 0;
}

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *fctx,
	     unsigned char *buf)
{
    struct ephemeral_state state = {
        .size_to_revoke = 0,
    };
    __sync_fetch_and_add(&faulted_size, 4096);
    __u64 used_size = donated_size + faulted_size;

    /*
     * Try to have at least EPH_MEM_DONATION_GRANULARITY of headroom, including
     * revocation requests in flight. If we don't have enough room, tell
     * userspace to revoke memory.
     */
    bpf_loop(MAX_CAS_LOOPS, revoke_cas_loop, &state, 0);

    if (state.size_to_revoke > 0) {
        __u64 *event;
        event = bpf_ringbuf_reserve(&revoke_event_rb, sizeof(*event), 0);
        if (!event) {
            return -1;
        }
        *event = state.size_to_revoke;
        bpf_ringbuf_submit(event, 0);
    }

    /*
     * If we are running low on memory, return non-zero to trigger a SIGBUS
     * which the userspace process should catch, and wait until more memory is
     * available.
     */
    if (used_size > backend_size) {
        return -1;
    }

    return 0;
}

SEC(".struct_ops.link")
struct fault_ops fault_ops = {
    .handle_page_fault = (void *)handle_page_fault,
    .handle_wp_fault = NULL,
};
