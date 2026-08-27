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
	return false;
}

void ebpf_fault_unload(struct EBPFFaultContext *ctx, HostMemoryBackend *backend)
{

}

int ebpf_fault_consume(struct EBPFFaultContext *ctx)
{
	return 0;
}
