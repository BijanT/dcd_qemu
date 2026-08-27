#ifndef QEMU_EBPF_BPF_FAULT_H
#define QEMU_EBPF_BPF_FAULT_H

#include "qapi/error.h"
#include "system/hostmem.h"

typedef struct EBPFFaultContext {
    void *obj; /* Opaque bpf_fault_bpf* */
    void *rb; /* Opaque struct ring_buffer* */
    void *bpf_link; /* Opaque pointer to struct bpf_link* */
    int program_fd;
    int epoll_fd;
} EBPFFaultContext;

void ebpf_fault_init(struct EBPFFaultContext *ctx);

bool ebpf_fault_is_loaded(struct EBPFFaultContext *ctx);

bool ebpf_fault_load(struct EBPFFaultContext *ctx, HostMemoryBackend *backend,
	Error **errp);

void ebpf_fault_unload(struct EBPFFaultContext *ctx, HostMemoryBackend *backend);

int ebpf_fault_consume(struct EBPFFaultContext *ctx);

#endif /* QEMU_EBPF_BPF_FAULT_H */