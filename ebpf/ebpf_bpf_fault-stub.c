#include "qemu/osdep.h"
#include "system/hostmem.h"

#include "ebpf/ebpf_bpf_fault.h"

void ebpf_fault_init(struct EBPFFaultContext *ctx) 
{

}

bool ebpf_fault_is_loaded(struct EBPFFaultContext *ctx)
{
	return false;
}

bool ebpf_fault_load(struct EBPFFaultContext *ctx, HostMemoryBackend *backend,
	Error **errp)
{
	error_setg(errp, "eBPF page-fault support has not been configured in this build.");
	return false;
}

void ebpf_fault_detach(struct EBPFFaultContext *ctx)
{

}

void ebpf_fault_destroy(struct EBPFFaultContext *ctx, HostMemoryBackend *backend)
{

}

int ebpf_fault_consume_revoke(struct EBPFFaultContext *ctx)
{
	return 0;
}

int ebpf_fault_consume_wait(struct EBPFFaultContext *ctx, uint64_t *addr)
{
	return 0;
}

int ebpf_fault_wake_all(struct EBPFFaultContext *ctx)
{
	return 0;
}
