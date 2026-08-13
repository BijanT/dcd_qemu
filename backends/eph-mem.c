#include "qemu/osdep.h"
#include "qemu/aio.h"
#include "qemu/error-report.h"
#include "qemu/lockable.h"
#include "qemu/main-loop.h"
#include "qemu/mmap-alloc.h"
#include "qemu/units.h"
#include "qemu/userfaultfd.h"
#include "qapi/qapi-commands-eph-mem.h"
#include "qapi/qapi-events-eph-mem.h"
#include "system/eph-mem.h"
#include "system/hostmem.h"
#include "qapi/error.h"

#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>

typedef struct EphMemBHRevokeData {
    char *backend_path;
    uint64_t size;
} EphMemBHRevokeData;

static void *eph_mem_zero_page = NULL;

static int eph_mem_uffd_copy(int uffd_fd, void *dst_addr, void *src_addr,
        uint64_t length, uint64_t *copied)
{
    struct uffdio_copy uffd_copy = {0};

    uffd_copy.dst = (uintptr_t) dst_addr;
    uffd_copy.src = (uintptr_t) src_addr;
    uffd_copy.len = length;
    uffd_copy.mode = 0;

    if (ioctl(uffd_fd, UFFDIO_COPY, &uffd_copy)) {
        if (copied) {
            *copied = uffd_copy.copy;
        }
        return -errno;
    }

    return 0;
}

static void eph_mem_revoke_memory(const char *backend_path, uint64_t size)
{
    static uint64_t next_id = 1;
    uint64_t id;

    if (size == 0) {
        return;
    }

    id = qatomic_fetch_inc(&next_id);
    qapi_event_send_eph_mem_revoke(backend_path, size, id);
}

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
    if (backend->userfault_fd == -1) {
        error_setg(errp, "Memory backend '%s' at %s is not initialized for "
                   "ephemeral memory",
                   object_get_typename(OBJECT(backend)), path);
        return NULL;
    }

    return backend;
}

static void eph_mem_revoke_memory_bh(void *opaque)
{
    EphMemBHRevokeData *data = opaque;

    eph_mem_revoke_memory(data->backend_path, data->size);
    g_free(data->backend_path);
    g_free(data);
}

/* Called with backend->userfault_mutex held */
static bool eph_mem_handler_live(HostMemoryBackend *backend, Error **errp)
{
    if (backend->userfault_thread_exit) {
        error_setg(errp, "Memory backend '%s' at %s is being torn down",
                   object_get_typename(OBJECT(backend)),
                   backend->userfault_path);
        return false;
    }

    return true;
}

/* Callers must hold backend->userfault_mutex */
static uint64_t eph_mem_get_used_size(HostMemoryBackend *backend)
{
    return backend->donated_size + backend->faulted_size;
}

/* Inspired by postcopy_ram_fault_thread */
static void *eph_mem_fault_thread(void *opaque)
{
    const int EPH_MEM_COPY_MAX_RETRIES = 3;
    HostMemoryBackend *backend = opaque;
    struct pollfd pollfds[2];
    size_t pagesize;
    void *ptr;
    uint64_t sz;
    uint64_t donated_size;
    int ret;
    uint64_t tmp;
    int retries;

    rcu_register_thread();

    pagesize = host_memory_backend_pagesize(backend);
    ptr = memory_region_get_ram_ptr(&backend->mr);
    sz = memory_region_size(&backend->mr);

    pollfds[0].fd = backend->userfault_fd;
    pollfds[0].events = POLLIN;
    pollfds[1].fd = backend->userfault_event_fd;
    pollfds[1].events = POLLIN;

    while (true) {
        ret = poll(pollfds, 2, -1);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            error_report("poll failed: %s", strerror(errno));
            goto unregister;
        }

        if (pollfds[1].revents & POLLIN) {
            /* Consume the signal */
            ret = read(backend->userfault_event_fd, &tmp, sizeof(tmp));
            if (ret != sizeof(tmp)) {
                error_report("Failed to read from userfault eventfd: %d",
                             ret < 0 ? -errno : ret);
            }
            /* Eventfd was signaled, time to exit */
            break;
        }

        /*
         * These are unlikely to occur. Just do a cursory check.
         */
        if ((pollfds[0].revents | pollfds[1].revents) &
            (POLLERR | POLLHUP | POLLNVAL)) {
            error_report("Unexpected poll revents: %d %d",
                         pollfds[0].revents, pollfds[1].revents);
            goto unregister;
        }

        if (pollfds[0].revents & POLLIN) {
            EphMemBHRevokeData *revoke_data;
            struct uffd_msg msg;
            uintptr_t aligned_addr;
            uint64_t used_size;
            int64_t headroom;
            uint64_t size_to_revoke;
            ssize_t nread;
            bool warned = false;

            /* TODO: Batch read fault messages */
            nread = read(backend->userfault_fd, &msg, sizeof(msg));
            if (nread != sizeof(msg)) {
                if (nread < 0 && errno == EAGAIN) {
                    /* No data to read, continue polling */
                    continue;
                } else if (nread < 0) {
                    error_report("Failed to read from userfaultfd: %s",
                                 strerror(errno));
                } else {
                    error_report("Read %zd bytes from userfaultfd, expected "
                                 "%zu", nread, sizeof(msg));
                }
                goto unregister;
            }

            if (msg.event != UFFD_EVENT_PAGEFAULT) {
                error_report("Unexpected event on userfaultfd: %u",
                             msg.event);
                continue;
            }

            /* Handle the page fault */
            aligned_addr = ROUND_DOWN(msg.arg.pagefault.address, pagesize);

            qemu_mutex_lock(&backend->userfault_mutex);
            /* Do we have enough memory to satisfy the request? */
            used_size = eph_mem_get_used_size(backend) + pagesize;
            /*
             * Try to always have at least EPH_MEM_DONATION_GRANULARITY of
             * headroom, including the revocation requests in flight.
             */
            headroom = backend->size + backend->revoked_size - used_size;
            size_to_revoke = MIN(EPH_MEM_DONATION_GRANULARITY,
                backend->donated_size - backend->revoked_size);
            if (headroom <= EPH_MEM_DONATION_GRANULARITY
                && size_to_revoke > 0) {
                backend->revoked_size += size_to_revoke;

                /*
                 * Defer sending to another thread so we don't block the
                 * userfault handler
                 */
                revoke_data = g_new(EphMemBHRevokeData, 1);
                revoke_data->backend_path = g_strdup(backend->userfault_path);
                revoke_data->size = size_to_revoke;
                aio_bh_schedule_oneshot(qemu_get_aio_context(),
                    eph_mem_revoke_memory_bh, revoke_data);
            }

            while (used_size > backend->size) {
                if (backend->userfault_thread_exit) {
                    qemu_mutex_unlock(&backend->userfault_mutex);
                    goto unregister;
                }

                /* Wait for memory to be returned */
                if (!qemu_cond_timedwait(&backend->userfault_cond,
                    &backend->userfault_mutex, 1000) && !warned) {
                    warn_report("%s: waiting for memory to be returned",
                                backend->userfault_path);
                    warned = true;
                }
                used_size = eph_mem_get_used_size(backend) + pagesize;
            }
            backend->faulted_size += pagesize;
            qemu_mutex_unlock(&backend->userfault_mutex);

            retries = 0;
retry:
            ret = eph_mem_uffd_copy(backend->userfault_fd,
                                 (void *)aligned_addr, eph_mem_zero_page,
                                 pagesize, NULL);
            if (ret < 0) {
                if (ret == -EAGAIN && retries < EPH_MEM_COPY_MAX_RETRIES) {
                    /* Try again */
                    retries++;
                    g_usleep(100);
                    goto retry;
                } else if (ret != -EEXIST) {
                    error_report("Failed to copy zero page to faulting address "
                                 "%p: %s",
                                 (void *)aligned_addr, strerror(-ret));
                    goto unregister;
                }
                qemu_mutex_lock(&backend->userfault_mutex);
                backend->faulted_size -= pagesize;
                qemu_mutex_unlock(&backend->userfault_mutex);
            }
        }
    }

unregister:
    qemu_mutex_lock(&backend->userfault_mutex);
    backend->userfault_thread_exit = true;
    donated_size = backend->donated_size - backend->revoked_size;
    backend->revoked_size += donated_size;
    qemu_mutex_unlock(&backend->userfault_mutex);

    /*
     * Since we can no longer process userfaults, revoke the memory.
     * We can directly call eph_mem_revoke_memory() here instead of using
     * aio_bh_schedule_oneshot() since we are no longer processing userfault
     * events, so there's no blocking concern.
     * TODO: Might want to separate out error case where the donor VM still
     * might need the memory vs. the shutdown case where the donor VM no longer
     * needs the memory.
     */
    eph_mem_revoke_memory(backend->userfault_path, donated_size);
    uffd_unregister_memory(backend->userfault_fd, ptr, sz);
    rcu_unregister_thread();
    return NULL;
}

int eph_mem_backend_init(HostMemoryBackend *backend, Error **errp)
{
    const size_t MAX_PAGESIZE = 2 * MiB;
    struct uffdio_api api_struct = {0};
    struct uffdio_register reg_struct;
    uint64_t ioctl_mask;
    void *ptr;
    uint64_t sz;
    size_t pagesize = host_memory_backend_pagesize(backend);

    if (pagesize > MAX_PAGESIZE) {
        error_setg(errp, "Page size %zu is larger than the maximum supported "
                   "page size %zu", pagesize, MAX_PAGESIZE);
        return -1;
    }

    if (!eph_mem_zero_page) {
        eph_mem_zero_page = qemu_ram_mmap(-1, MAX_PAGESIZE, MAX_PAGESIZE,
                                          QEMU_MAP_READONLY, 0);
        if (eph_mem_zero_page == MAP_FAILED) {
            error_setg(errp, "Failed to allocate zero page");
            eph_mem_zero_page = NULL;
            return -1;
        }
    }

    if (!QEMU_IS_ALIGNED(backend->size, pagesize)) {
        error_setg(errp, "'donatable=on' requires size to be multiple of the "
                   "page size %zx", pagesize);
        return -1;
    }

    /*
     * Disable discarding ram blocks. This is to prevent us from overcounting
     * faulted in memory after some of the memory have been removed, say from
     * ballooning.
     * TODO: Replace this with a RamDiscardListener that can be used to signal
     * when RAM is being removed instead of this heavy handed approach.
     */
    if (ram_block_discard_disable(true)) {
        error_setg(errp, "Failed to disable ram block discarding");
        return -1;
    }

    backend->userfault_fd = uffd_open(O_CLOEXEC | O_NONBLOCK);
    if (backend->userfault_fd < 0) {
        backend->userfault_fd = -1;
        error_setg_errno(errp, errno, "Userfaultfd not available");
        goto enable_discard;
    }

    backend->userfault_path = object_get_canonical_path(OBJECT(backend));
    if (!backend->userfault_path) {
        error_setg(errp, "Failed to get canonical path for memory backend");
        goto cleanup_uffd;
    }

    api_struct.api = UFFD_API;
    api_struct.features = 0;
    if (ioctl(backend->userfault_fd, UFFDIO_API, &api_struct)) {
        error_setg_errno(errp, errno, "UFFDIO_API failed");
        goto cleanup_path;
    }
    ioctl_mask = 1ULL << _UFFDIO_REGISTER | 1ULL << _UFFDIO_UNREGISTER;
    if ((api_struct.ioctls & ioctl_mask) != ioctl_mask) {
        error_setg(errp, "Missing userfault features: %" PRIx64,
                   (uint64_t)(~api_struct.ioctls & ioctl_mask));
        goto cleanup_path;
    }

    ptr = memory_region_get_ram_ptr(&backend->mr);
    sz = memory_region_size(&backend->mr);
    reg_struct.range.start = (uintptr_t)ptr;
    reg_struct.range.len = sz;
    reg_struct.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(backend->userfault_fd, UFFDIO_REGISTER, &reg_struct)) {
        error_setg_errno(errp, errno, "UFFDIO_REGISTER failed");
        goto cleanup_path;
    }
    if (!(reg_struct.ioctls & (1ULL << _UFFDIO_COPY))) {
        error_setg(errp, "Region doesn't support COPY");
        goto cleanup_path;
    }

    backend->userfault_event_fd = eventfd(0, EFD_CLOEXEC);
    if (backend->userfault_event_fd == -1) {
        error_setg_errno(errp, errno, "Failed to create userfault eventfd");
        goto cleanup_path;
    }

    qemu_mutex_init(&backend->userfault_mutex);
    qemu_cond_init(&backend->userfault_cond);

    qemu_thread_create(&backend->userfault_thread, "eph-mem-fault",
                       eph_mem_fault_thread, backend, QEMU_THREAD_JOINABLE);

    return 0;
cleanup_path:
    g_free(backend->userfault_path);
    backend->userfault_path = NULL;
cleanup_uffd:
    close(backend->userfault_fd);
    backend->userfault_fd = -1;
enable_discard:
    ram_block_discard_disable(false);
    return -1;
}

static void eph_mem_notify_fault_thread(HostMemoryBackend *backend)
{
    uint64_t tmp = 1;
    ssize_t nwrite;

    nwrite = write(backend->userfault_event_fd, &tmp, sizeof(tmp));
    if (nwrite != sizeof(tmp)) {
        error_report("Failed to notify fault thread: %s",
                     nwrite < 0 ? strerror(errno) : "short write");
    }
}

void eph_mem_backend_finalize(HostMemoryBackend *backend)
{
    /* Check if ephemeral memory stuff has been initialized */
    if (backend->userfault_fd == -1) {
        return;
    }

    /* First, end the fault thread to make sure it's done working */
    qemu_mutex_lock(&backend->userfault_mutex);
    backend->userfault_thread_exit = true;
    qemu_cond_broadcast(&backend->userfault_cond);
    qemu_mutex_unlock(&backend->userfault_mutex);
    eph_mem_notify_fault_thread(backend);
    qemu_thread_join(&backend->userfault_thread);
    g_free(backend->userfault_path);
    backend->userfault_path = NULL;

    qemu_mutex_destroy(&backend->userfault_mutex);
    qemu_cond_destroy(&backend->userfault_cond);

    ram_block_discard_disable(false);

    close(backend->userfault_fd);
    close(backend->userfault_event_fd);
    backend->userfault_fd = -1;
    backend->userfault_event_fd = -1;
}

EphMemDonateResult *qmp_eph_mem_donate_capacity(const char *path, uint64_t size,
    Error **errp)
{
    HostMemoryBackend *backend;
    EphMemDonateResult *result;
    uint64_t donated_size = 0;
    uint64_t remaining_size;

    if (size == 0) {
        error_setg(errp, "Cannot donate zero bytes");
        return NULL;
    }

    if (!QEMU_IS_ALIGNED(size, EPH_MEM_DONATION_GRANULARITY)) {
        error_setg(errp, "Donation size %" PRIu64 " is not a multiple of the "
                   "donation granularity %" PRIi64,
                   size, EPH_MEM_DONATION_GRANULARITY);
        return NULL;
    }

    backend = eph_mem_backend_from_path(path, errp);
    if (!backend) {
        return NULL;
    }

    WITH_QEMU_LOCK_GUARD(&backend->userfault_mutex) {
        if (!eph_mem_handler_live(backend, errp)) {
            return NULL;
        }
        /* If a revocation request is in flight, don't allow new donations */
        if (backend->revoked_size > 0) {
            donated_size = 0;
            break;
        }
        /*
         * Only whole blocks can be granted, so a backend whose size is not a
         * multiple of the granularity keeps a permanently undonatable tail.
         * Also, make sure we have at least EPH_MEM_DONATION_GRANULARITY of
         * headroom.
         */
        remaining_size = backend->size - eph_mem_get_used_size(backend);
        remaining_size = QEMU_ALIGN_DOWN(remaining_size,
            EPH_MEM_DONATION_GRANULARITY);

        if (remaining_size >= EPH_MEM_DONATION_GRANULARITY) {
            remaining_size -= EPH_MEM_DONATION_GRANULARITY;
        }

        donated_size = MIN(size, remaining_size);

        backend->donated_size += donated_size;
    }
    result = g_malloc0(sizeof(*result));
    result->granted = donated_size;
    return result;
}

void qmp_eph_mem_return_capacity(const char *path, uint64_t size, bool has_id,
    int64_t id, Error **errp)
{
    HostMemoryBackend *backend;

    /*
     * TODO: If id exists, check that it matches an in flight revocation
     * request.
     */

    if (size == 0) {
        error_setg(errp, "Cannot return zero bytes");
        return;
    }

    if (!QEMU_IS_ALIGNED(size, EPH_MEM_DONATION_GRANULARITY)) {
        error_setg(errp, "Returned size %" PRIu64 " is not a multiple of the "
                   "donation granularity %" PRIi64,
                   size, EPH_MEM_DONATION_GRANULARITY);
        return;
    }

    backend = eph_mem_backend_from_path(path, errp);
    if (!backend) {
        return;
    }

    WITH_QEMU_LOCK_GUARD(&backend->userfault_mutex) {
        /*
         * We don't check eph_mem_handler_live() here because when the fault
         * thread exits on error, it revokes all the remaining donated memory.
         * We still want to account for the orchestrator's reply here.
         * Backends torn down via finalize are freed first, so responses from
         * those revocation requests will never reach here.
         */

        if (size > backend->donated_size) {
            error_setg(errp, "Cannot return %" PRIu64 " bytes from memory "
                       "backend '%s' at %s. Has donated %" PRIu64 " bytes",
                       size, object_get_typename(OBJECT(backend)), path,
                       backend->donated_size);
            return;
        }

        backend->donated_size -= size;
        /*
         * We could get returned capacity not related to revocation requests,
         * so make sure we don't underflow backend->revoked_size
         */
        backend->revoked_size -= MIN(size, backend->revoked_size);
        qemu_cond_broadcast(&backend->userfault_cond);
    }
}
