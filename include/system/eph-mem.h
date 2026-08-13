#ifndef SYSTEM_EPH_MEM_H
#define SYSTEM_EPH_MEM_H

#include "system/hostmem.h"
#include "qapi/error.h"
#include "qemu/units.h"

#define EPH_MEM_DONATION_GRANULARITY ((int64_t)256 * MiB)

#ifdef CONFIG_LINUX

int eph_mem_backend_init(HostMemoryBackend *backend, Error **errp);
void eph_mem_backend_finalize(HostMemoryBackend *backend);

#else

static inline int eph_mem_backend_init(HostMemoryBackend *backend, Error **errp)
{
    return 0;
}

static inline void eph_mem_backend_finalize(HostMemoryBackend *backend)
{
}

#endif /* CONFIG_LINUX */

#endif /* SYSTEM_EPH_MEM_H */
