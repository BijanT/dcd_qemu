#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "system/hostmem.h"
#include "system/eph-mem.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "ebpf/ebpf_bpf_fault.h"
#include "ebpf/bpf_fault.bpf.skeleton.h"

static int handle_revoke_event(void *ctx, void *data, size_t data_sz)
{
    HostMemoryBackend *backend = ctx;
    uint64_t size_to_revoke = *(uint64_t *)data;

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
        ctx->epoll_fd = -1;
    }
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
    int ret;

    g_assert(!ebpf_fault_is_loaded(ctx));

    bpf_fault_ctx = bpf_fault_bpf__open();
    if (!bpf_fault_ctx) {
	error_setg(errp, "Unable to open eBPF program");
	return false;
    }

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

    ret = bpf_fault_bpf__attach(bpf_fault_ctx);
    if (ret) {
	error_setg(errp, "Unable to attach eBPF program");
	goto error;
    }

    link = bpf_map__attach_fault_ops(bpf_fault_ctx->maps.fault_ops,
        backend_ptr, backend_size, 0);
    if (!link) {
	error_setg(errp, "Unable to setup bpf fault ops");
	goto error;
    }
    ctx->bpf_link = link;

    return true;

error:
    bpf_fault_bpf__destroy(bpf_fault_ctx);
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    ctx->obj = NULL;
    ctx->rb = NULL;
    ctx->bpf_link = NULL;
    ctx->program_fd = -1;
    ctx->epoll_fd = -1;
    backend->revoked_size = NULL;
    backend->donated_size = NULL;
    backend->faulted_size = NULL;
    return false;
}

void ebpf_fault_unload(struct EBPFFaultContext *ctx, HostMemoryBackend *backend)
{
    if (!ebpf_fault_is_loaded(ctx)) {
        return;
    }

    ring_buffer__free(ctx->rb);
    bpf_link__destroy(ctx->bpf_link);
    bpf_fault_bpf__destroy(ctx->obj);

    ctx->obj = NULL;
    ctx->rb = NULL;
    ctx->bpf_link = NULL;
    ctx->program_fd = -1;
    ctx->epoll_fd = -1;

    if (backend) {
        backend->revoked_size = NULL;
        backend->donated_size = NULL;
        backend->faulted_size = NULL;
    }
}

int ebpf_fault_consume(struct EBPFFaultContext *ctx)
{
    g_assert(ebpf_fault_is_loaded(ctx));

    return ring_buffer__consume(ctx->rb);
}