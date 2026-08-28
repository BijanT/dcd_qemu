#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPH_MEM_DONATION_GRANULARITY ((__s64)256 * 1024 * 1024)
/*
 * Give plenty of chances for CAS to succeed. It should never actually get this
 * high in practice.
 */
#define MAX_CAS_LOOPS 1000
#define PAGE_SIZE 4096

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

struct admit_state {
    __u8 admit;
};

struct revoke_state {
    __u64 size_to_revoke;
};

const __u64 num_vcpus = 0;
const __u64 backend_size = 0;
volatile __u64 donated_size = 0;
volatile __u64 revoked_size = 0;
volatile __u64 faulted_size = 0;

/*
 * Atomically increments faulted_size as long as there is enough room for the
 * new request. While a page is allocated before bpf_fault calls
 * handle_page_fault(), that page is returned if handle_page_fault() returns an
 * error. That means we only want to increment faulted_size if
 * handle_page_fault() succeeds.
 */
static long admit_fault_cas_loop(__u32 index, void *ctx)
{
    struct admit_state *state = ctx;
    __u64 old_faulted_size = faulted_size;
    __u64 new_faulted_size = old_faulted_size + PAGE_SIZE;
    __u64 local_donated_size = donated_size;
    __u64 buffer_size = num_vcpus * PAGE_SIZE;
    __u64 used_size = local_donated_size + new_faulted_size;
    __u64 cas_ret;

    /*
     * bpf_fault can allocate multiple pages in parallel, so we need to have a
     * buffer proportional to the number of vCPUs to ensure we never
     * overallocate memory. However, if the backend has not donated any memory,
     * we are free to ignore this buffer, since the VM has all of its memory.
     */
    if (local_donated_size > 0) {
        used_size += buffer_size;
    }

    /* Do we have enough space? */
    if (used_size > backend_size) {
        state->admit = 0;
        return 1;
    }

    cas_ret = __sync_val_compare_and_swap(&faulted_size, old_faulted_size,
        new_faulted_size);
    if (cas_ret != old_faulted_size) {
        /* We lost the race. Try again. */
        state->admit = 0;
        return 0;
    }

    /*
     * We won the race!
     * Check against the race condition that the donated_size was increased.
     * If this is the case, we should retry the CAS operation.
     */
    if (donated_size > local_donated_size) {
        __sync_fetch_and_sub(&faulted_size, PAGE_SIZE);
        state->admit = 0;
        return 0;
    }

    state->admit = 1;
    return 1;
}

/* Atomically updates the revoked size if running low on memory */
static long revoke_cas_loop(__u32 index, void *ctx)
{
    struct revoke_state *state = ctx;
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
    /*
     * donated_size can be transiently less than revoked_size in
     * qmp_eph_mem_return_capacity(). In any case, if that is true, we have
     * nothing to revoke.
     */
    if (local_donated_size < old_revoked_size) {
        size_to_revoke = 0;
    } else {
        size_to_revoke = MIN(EPH_MEM_DONATION_GRANULARITY,
            local_donated_size - old_revoked_size);
    }

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
    struct admit_state adm_state = {
        .admit = 0,
    };
    struct revoke_state rev_state = {
        .size_to_revoke = 0,
    };

    /*
     * Try to have at least EPH_MEM_DONATION_GRANULARITY of headroom, including
     * revocation requests in flight. If we don't have enough room, tell
     * userspace to revoke memory.
     */
    bpf_loop(MAX_CAS_LOOPS, revoke_cas_loop, &rev_state, 0);

    if (rev_state.size_to_revoke > 0) {
        __u64 *event;
        event = bpf_ringbuf_reserve(&revoke_event_rb, sizeof(*event), 0);
        if (event) {
            *event = rev_state.size_to_revoke;
            bpf_ringbuf_submit(event, 0);
        } else {
            /*
             * Ring buffer is full: skip the revocation notification this time.
             * The next fault will try to handle it. Just print something for
             * debugging purposes.
             */
            bpf_printk("Ring buffer is full, skipping notification\n");
        }
    }

    /*
     * Determine if we should admit this fault, or if we should wait for memory
     * to be returned.
     */
    bpf_loop(MAX_CAS_LOOPS, admit_fault_cas_loop, &adm_state, 0);
    if (!adm_state.admit) {
        return -1;
    }

    return 0;
}

SEC(".struct_ops.link")
struct fault_ops fault_ops = {
    .handle_page_fault = (void *)handle_page_fault,
    .handle_wp_fault = NULL,
};
