#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/units.h"
#include "qapi/qapi-commands-eph-mem.h"
#include "system/hostmem.h"
#include "qapi/error.h"

#define EPH_MEM_DONATION_GRANULARITY ((uint64_t)256 * MiB)

static HostMemoryBackend *eph_mem_backend_from_path(const char *path,
    Error **errp)
{
    Object *obj;
    HostMemoryBackend *backend;
    bool ambiguous = false;

    obj = object_resolve_path_type(path, TYPE_MEMORY_BACKEND, &ambiguous);
    if (ambiguous) {
        error_setg(errp, "Object '%s' is ambiguous", path);
        return NULL;
    }
    if (!obj) {
        error_setg(errp, "Object '%s' not found or is not a memory backend",
                   path);
        return NULL;
    }
    backend = MEMORY_BACKEND(obj);

    if (!backend->donatable) {
        error_setg(errp, "Memory backend '%s' at %s is not donatable",
                   object_get_typename(OBJECT(backend)), path);
        return NULL;
    }

    return backend;
}

EphMemDonateResult *qmp_eph_mem_donate_capacity(const char *path, uint64_t size,
    Error **errp)
{
    HostMemoryBackend *backend;
    EphMemDonateResult *result;
    uint64_t donated_size;
    uint64_t remaining_size;

    if (size == 0) {
        error_setg(errp, "Cannot donate zero bytes");
        return NULL;
    }

    if (!QEMU_IS_ALIGNED(size, EPH_MEM_DONATION_GRANULARITY)) {
        error_setg(errp, "Donation size %" PRIu64 " is not a multiple of the "
                   "donation granularity %" PRIu64,
                   size, EPH_MEM_DONATION_GRANULARITY);
        return NULL;
    }

    backend = eph_mem_backend_from_path(path, errp);
    if (!backend) {
        return NULL;
    }

    /*
     * Writes are serialized by the BQL, so there is no read-then-use race.
     * Still use qatomic_read for consistency.
     */
    assert(bql_locked());
    donated_size = qatomic_read(&backend->donated_size);
    /*
     * Only whole blocks can be granted, so a backend whose size is not a
     * multiple of the granularity keeps a permanently undonatable tail.
     */
    remaining_size = QEMU_ALIGN_DOWN(backend->size - donated_size,
                                     EPH_MEM_DONATION_GRANULARITY);
    size = MIN(size, remaining_size);

    qatomic_set(&backend->donated_size, donated_size + size);
    result = g_malloc0(sizeof(*result));
    result->granted = size;
    return result;
}

void qmp_eph_mem_return_capacity(const char *path, uint64_t size, bool has_id,
    int64_t id, Error **errp)
{
    HostMemoryBackend *backend;
    uint64_t donated_size;

    /*
     * TODO: If id exists, check that it matches an in flight revocation
     * request. We do not currently issue revocation requests, so there is
     * currently nothing to check.
     */

    if (size == 0) {
        error_setg(errp, "Cannot return zero bytes");
        return;
    }

    if (!QEMU_IS_ALIGNED(size, EPH_MEM_DONATION_GRANULARITY)) {
        error_setg(errp, "Returned size %" PRIu64 " is not a multiple of the "
                   "donation granularity %" PRIu64,
                   size, EPH_MEM_DONATION_GRANULARITY);
        return;
    }

    backend = eph_mem_backend_from_path(path, errp);
    if (!backend) {
        return;
    }

    /*
     * Writes are serialized by the BQL, so there is no read-then-use race.
     * Still use qatomic_read for consistency.
     */
    assert(bql_locked());
    donated_size = qatomic_read(&backend->donated_size);
    if (size > donated_size) {
        error_setg(errp, "Cannot return %" PRIu64 " bytes from memory "
                   "backend '%s' at %s. Has donated %" PRIu64 " bytes",
                   size, object_get_typename(OBJECT(backend)), path,
                   donated_size);
        return;
    }

    qatomic_set(&backend->donated_size, donated_size - size);
}
