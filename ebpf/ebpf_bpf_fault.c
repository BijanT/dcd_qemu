#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "hw/core/boards.h"
#include "system/hostmem.h"
#include "system/eph-mem.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ebpf/ebpf_bpf_fault.h"
#include "ebpf/bpf_fault.bpf.skeleton.h"

static int handle_revoke_event(void *ctx, void *data, size_t data_sz)
{
    HostMemoryBackend *backend = ctx;
    uint64_t size_to_revoke;

    if (data_sz != sizeof(size_to_revoke)) {
        error_report("handle_revoke_event: Expected data size of %zu, got %zu",
            sizeof(size_to_revoke), data_sz);
        return 0;
    }
    size_to_revoke = *(uint64_t *)data;

    eph_mem_revoke_memory(backend->canonical_path, size_to_revoke);
    return 0;
}

void ebpf_fault_init(struct EBPFFaultContext *ctx)
{
    if (ctx != NULL) {
        ctx->obj = NULL;
        ctx->rb = NULL;
        ctx->bpf_link = NULL;
        ctx->program_fd = -1;
        ctx->link_fd = -1;
        ctx->epoll_fd = -1;
        ctx->page_size = 0;
        ctx->num_vcpus = 0;
    }
}

static bool ebpf_fault_is_attached(struct EBPFFaultContext *ctx)
{
    return ctx != NULL && ctx->bpf_link != NULL;
}

bool ebpf_fault_is_loaded(struct EBPFFaultContext *ctx)
{
    return ctx != NULL && (ctx->obj != NULL || ctx->program_fd != -1);
}

bool ebpf_fault_load(struct EBPFFaultContext *ctx, HostMemoryBackend *backend,
    Error **errp)
{
    struct bpf_fault_bpf *bpf_fault_ctx = NULL;
    struct ring_buffer *rb = NULL;
    struct bpf_link *link = NULL;
    void *backend_ptr = memory_region_get_ram_ptr(&backend->mr);
    uint64_t backend_size = memory_region_size(&backend->mr);
    size_t page_size = host_memory_backend_pagesize(backend);
    int old_link_flags;

    g_assert(!ebpf_fault_is_loaded(ctx));

    bpf_fault_ctx = bpf_fault_bpf__open();
    if (!bpf_fault_ctx) {
        error_setg(errp, "Unable to open eBPF program");
        return false;
    }

    /* This shouldn't happen, but guard with a reasonably large value in case */
    if (!current_machine || !current_machine->smp.max_cpus) {
        warn_report("Failed to retrieve max_cpus from current machine, using "
            "default value of 128");
        ctx->num_vcpus = 128;
    } else {
        ctx->num_vcpus = current_machine->smp.max_cpus;
    }
    bpf_fault_ctx->rodata->num_vcpus = ctx->num_vcpus;
    bpf_fault_ctx->rodata->backend_size = backend_size;
    ctx->obj = bpf_fault_ctx;

    if (bpf_fault_bpf__load(ctx->obj)) {
        error_setg(errp, "Unable to load eBPF program");
        goto error;
    }

    rb = ring_buffer__new(bpf_map__fd(bpf_fault_ctx->maps.revoke_event_rb),
    	handle_revoke_event, backend, NULL);
    if (!rb) {
        error_setg(errp, "Unable to create ring buffer");
        goto error;
    }
    ctx->rb = rb;
    ctx->epoll_fd = ring_buffer__epoll_fd(rb);

    ctx->program_fd = bpf_program__fd(bpf_fault_ctx->progs.handle_page_fault);
    backend->revoked_size = (uint64_t *)&bpf_fault_ctx->bss->revoked_size;
    backend->donated_size = (uint64_t *)&bpf_fault_ctx->bss->donated_size;
    backend->faulted_size = (uint64_t *)&bpf_fault_ctx->bss->faulted_size;

    link = bpf_map__attach_fault_ops(bpf_fault_ctx->maps.fault_ops,
        backend_ptr, backend_size, 0);
    if (!link) {
        error_setg(errp, "Unable to setup bpf fault ops");
        goto error;
    }
    ctx->bpf_link = link;
    ctx->link_fd = bpf_link__fd(link);
    old_link_flags = fcntl(ctx->link_fd, F_GETFL);
    if (old_link_flags < 0) {
        error_setg_errno(errp, errno, "Unable to get bpf link fd flags");
        goto error;
    }
    if (fcntl(ctx->link_fd, F_SETFL, old_link_flags | O_NONBLOCK)< 0) {
        error_setg_errno(errp, errno, "Unable to set bpf link fd to non-blocking");
        goto error;
    }

    if (page_size > (2 * MiB)) {
        error_setg(errp, "eBPF fault only supports up to 2MB pages, but backend has "
            "page size of %zu", page_size);
        goto error;
    }
    ctx->page_size = page_size;

    return true;

error:
    bpf_fault_bpf__destroy(bpf_fault_ctx);
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    ctx->obj = NULL;
    ctx->rb = NULL;
    ctx->bpf_link = NULL;
    ctx->link_fd = -1;
    ctx->program_fd = -1;
    ctx->epoll_fd = -1;
    ctx->page_size = 0;
    ctx->num_vcpus = 0;
    backend->revoked_size = NULL;
    backend->donated_size = NULL;
    backend->faulted_size = NULL;
    return false;
}

void ebpf_fault_detach(struct EBPFFaultContext *ctx)
{
    if (!ebpf_fault_is_attached(ctx)) {
        return;
    }

    ring_buffer__free(ctx->rb);
    bpf_link__destroy(ctx->bpf_link);

    ctx->rb = NULL;
    ctx->bpf_link = NULL;
    ctx->link_fd = -1;
    ctx->epoll_fd = -1;
}

void ebpf_fault_destroy(struct EBPFFaultContext *ctx, HostMemoryBackend *backend)
{
    bpf_fault_bpf__destroy(ctx->obj);
    ctx->obj = NULL;
    ctx->program_fd = -1;

    if (backend) {
        backend->revoked_size = NULL;
        backend->donated_size = NULL;
        backend->faulted_size = NULL;
    }
}

int ebpf_fault_consume_revoke(struct EBPFFaultContext *ctx)
{
    g_assert(ebpf_fault_is_attached(ctx));

    return ring_buffer__consume(ctx->rb);
}

int ebpf_fault_consume_wait(struct EBPFFaultContext *ctx, uint64_t *addr)
{
    struct bpf_fault_msg msg;
    int ret;

    g_assert(ebpf_fault_is_attached(ctx));

    ret = read(ctx->link_fd, &msg, sizeof(msg));
    if (ret < 0) {
        return -errno;
    } else if (ret != sizeof(msg)) {
        return -EIO;
    }

    if (addr) {
        *addr = msg.address;
    }
    return 0;
}

int ebpf_fault_wake_all(struct EBPFFaultContext *ctx)
{
    g_assert(ebpf_fault_is_attached(ctx));

    /*
     * Using start = 0, len = UINT64_MAX signals to wake all waiting
     * bpf fault threads.
     */
    return bpf_link__fault_wake(ctx->link_fd, 0, UINT64_MAX);
}
