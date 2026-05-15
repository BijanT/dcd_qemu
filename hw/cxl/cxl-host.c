/*
 * CXL host parameter parsing routines
 *
 * Copyright (c) 2022 Huawei
 * Modeled loosely on the NUMA options handling in hw/core/numa.c
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/bitmap.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "system/qtest.h"
#include "hw/core/boards.h"

#include "qapi/qapi-visit-machine.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_host.h"
#include "hw/pci/pci_bus.h"
#include "hw/pci/pci_bridge.h"
#include "hw/pci/pci_host.h"
#include "hw/pci/pcie_port.h"
#include "hw/pci-bridge/pci_expander_bridge.h"

static void cxl_fixed_memory_window_config(CXLFixedMemoryWindowOptions *object,
                                           int index, Error **errp)
{
    ERRP_GUARD();
    DeviceState *dev = qdev_new(TYPE_CXL_FMW);
    CXLFixedWindow *fw = CXL_FMW(dev);
    strList *target;
    int i;

    qemu_log("cxl_fixed_memory_window_config called %d\n", index);

    fw->index = index;

    for (target = object->targets; target; target = target->next) {
        fw->num_targets++;
    }

    fw->enc_int_ways = cxl_interleave_ways_enc(fw->num_targets, errp);
    if (*errp) {
        return;
    }

    if (object->size % (256 * MiB)) {
        error_setg(errp,
                   "Size of a CXL fixed memory window must be a multiple of 256MiB");
        return;
    }
    fw->size = object->size;

    if (object->has_interleave_granularity) {
        fw->enc_int_gran =
            cxl_interleave_granularity_enc(object->interleave_granularity,
                                           errp);
        if (*errp) {
            return;
        }
    } else {
        /* Default to 256 byte interleave */
        fw->enc_int_gran = 0;
    }

    if (object->has_use_ram && fw->num_targets == 1) {
        fw->use_ram = object->use_ram;
    } else {
        if (object->has_use_ram && fw->num_targets != 1) {
            error_setg(errp, "use-ram=true is only supported for a single target");
        }
        fw->use_ram = false;
    }

    fw->targets = g_malloc0_n(fw->num_targets, sizeof(*fw->targets));
    for (i = 0, target = object->targets; target; i++, target = target->next) {
        /* This link cannot be resolved yet, so stash the name for now */
        fw->targets[i] = g_strdup(target->value);
    }
    /*
     * Arbitrary size for now. Ideally should be the block size of the device.
     * It should be no bigger than 256 MiB because that's what DCD regions are
     * aligned to and we probably don't want a DC alias to span across multiple
     * regions.
     */
    fw->dc_alias_size = 256 * MiB;

    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), errp);
}

static Object *cxl_fmw_get_link(Object *obj, const char *name)
{
    Error *local_err = NULL;
    Object *link = object_property_get_link(obj, name, &local_err);

    if (local_err) {
        qemu_log("Error resolving link for %s\n", name);
        warn_report_err(local_err);
        return NULL;
    }

    return link;
}

static void cxl_print_memory_region_hierarchy(MemoryRegion *mr, int level)
{
    MemoryRegion *subregion;

    qemu_log("%*sMemoryRegion: %s: %lx-%lx\n", level * 2, " ", mr->name, (unsigned long)mr->addr, (unsigned long)(mr->addr + mr->size));
    QTAILQ_FOREACH(subregion, &mr->subregions, subregions_link) {
        cxl_print_memory_region_hierarchy(subregion, level + 1);
        if (subregion == mr) {
            qemu_log("%*sMemoryRegion %s contains itself\n", (level + 1) * 2, " ", subregion->name);
        }
    }
}

static  uint64_t cxl_add_fixed_window_subregion(CXLFixedWindow *fw,
    MemoryRegion *src, MemoryRegion *alias, const char *alias_name,
    uint64_t fw_offset, uint64_t alias_offset, uint64_t alias_size)
{
    if (alias_size == 0)
        alias_size = memory_region_size(src);

    memory_region_init_alias(alias, OBJECT(fw), alias_name, src, alias_offset,
                             alias_size);
    memory_region_set_enabled(alias, false);
    memory_region_add_subregion_overlap(&fw->mr, fw_offset, alias, 1);

    fw_offset += alias_size;

    return fw_offset;
}

static void cxl_setup_ram_regions(CXLFixedWindow *fw, PXBCXLDev *pxb)
{
    uint64_t offset = 0;
    Error *local_err = NULL;
    PCIDevice *d = NULL;
    PCIHostState *hb = NULL;
    PCIDevice *rp = NULL;
    Object *memdev = NULL;
    MemoryRegion *mr = NULL;

    if (fw->num_targets != 1) {
        error_setg(&local_err, "use-ram=true requires exactly one target");
        goto not_ram;
    }
    hb = PCI_HOST_BRIDGE(pxb->cxl_host_bridge);
    rp = pcie_find_port_first(hb->bus);
    if (!rp) {
        error_setg(&local_err, "Could not find root port for RAM-backed fixed memory window");
        goto not_ram;
    }

    d = pci_bridge_get_sec_bus(PCI_BRIDGE(rp))->devices[0];
    if (!d || !object_dynamic_cast(OBJECT(d), TYPE_CXL_TYPE3)) {
        error_setg(&local_err, "Could not find CXL Type 3 target.");
        goto not_ram;
    }

    /* Add subregions for each memory device */
    memdev = cxl_fmw_get_link(OBJECT(d), "volatile-memdev");
    if (memdev) {
        mr = host_memory_backend_get_memory(MEMORY_BACKEND(memdev));
        if (mr) {
            offset = cxl_add_fixed_window_subregion(fw, mr, &fw->vmem_alias,
                "volatile-region", offset, 0, 0);
        }
    }
    memdev = cxl_fmw_get_link(OBJECT(d), "persistent-memdev");
    if (memdev) {
        mr = host_memory_backend_get_memory(MEMORY_BACKEND(memdev));
        if (mr) {
            offset = cxl_add_fixed_window_subregion(fw, mr, &fw->pmem_alias,
                "persistent-region", offset, 0, 0);
        }
    }
    memdev = cxl_fmw_get_link(OBJECT(d), "volatile-dc-memdev");
    if (memdev) {
        mr = host_memory_backend_get_memory(MEMORY_BACKEND(memdev));
        if (mr) {
            char *alias_name;
            uint64_t dc_region_size = memory_region_size(mr);

            fw->num_dc_aliases = dc_region_size / fw->dc_alias_size;
            if (dc_region_size % fw->dc_alias_size)
                fw->num_dc_aliases++;
            fw->dc_aliases = g_new(MemoryRegion, fw->num_dc_aliases);
            for (int i = 0; i < fw->num_dc_aliases; i++) {
                uint64_t alias_offset = i * fw->dc_alias_size;
                uint64_t alias_size = MIN(fw->dc_alias_size, dc_region_size - alias_offset);
                alias_name = g_strdup_printf("volatile-dc-region-%d", i);
                offset = cxl_add_fixed_window_subregion(fw, mr, &fw->dc_aliases[i],
                    alias_name, offset, alias_offset, alias_size);
                g_free(alias_name);
            }
        }
    }

    if (offset != fw->size) {
        error_setg(&local_err, "Size of memory devices does not match fixed window size");
        goto not_ram;
    }

    return;
not_ram:
    /* TODO: cleanly unwind the RAM-backed setup and fall back instead of
     * terminating QEMU here.
     */
    if (local_err)
        error_report_err(local_err);
    exit(EXIT_FAILURE);
}

static int cxl_fmws_link(Object *obj, void *opaque)
{
    Error **errp = opaque;
    struct CXLFixedWindow *fw;
    int i;

    if (!object_dynamic_cast(obj, TYPE_CXL_FMW)) {
        return 0;
    }
    fw = CXL_FMW(obj);

    qemu_log("cxl_fmws_link called %d %s\n", fw->num_targets, fw->targets[0]);
    for (i = 0; i < fw->num_targets; i++) {
        Object *o;
        bool ambig;

        o = object_resolve_path_type(fw->targets[i], TYPE_PXB_CXL_DEV,
                                     &ambig);
        if (!o) {
            qemu_log("Could not resolve path %s %d\n", fw->targets[i], ambig);
            error_setg(errp, "Could not resolve CXLFM target %s",
                       fw->targets[i]);
            return -1;
        }
        fw->target_hbs[i] = PXB_CXL_DEV(o);
    }

    /*
     * This must be done here because we can only find the MemoryRegions of the
     * underlying device after link resolution.
     */
    if (fw->use_ram) {
        cxl_setup_ram_regions(fw, fw->target_hbs[0]);
        cxl_print_memory_region_hierarchy(&fw->mr, 0);
    }

    return 0;
}

void cxl_fmws_link_targets(Error **errp)
{
    /* Order doesn't matter for this, so no need to build list */
    object_child_foreach_recursive(object_get_root(), cxl_fmws_link, errp);
}

static bool cxl_hdm_find_target(uint32_t *cache_mem, hwaddr addr,
                                uint8_t *target)
{
    int hdm_inc = R_CXL_HDM_DECODER1_BASE_LO - R_CXL_HDM_DECODER0_BASE_LO;
    unsigned int hdm_count;
    bool found = false;
    int i;
    uint32_t cap;

    cap = ldl_le_p(cache_mem + R_CXL_HDM_DECODER_CAPABILITY);
    hdm_count = cxl_decoder_count_dec(FIELD_EX32(cap,
                                                 CXL_HDM_DECODER_CAPABILITY,
                                                 DECODER_COUNT));
    for (i = 0; i < hdm_count; i++) {
        uint32_t ctrl, ig_enc, iw_enc, target_idx;
        uint32_t low, high;
        uint64_t base, size;

        low = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_BASE_LO + i * hdm_inc);
        high = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_BASE_HI + i * hdm_inc);
        base = (low & 0xf0000000) | ((uint64_t)high << 32);
        low = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_SIZE_LO + i * hdm_inc);
        high = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_SIZE_HI + i * hdm_inc);
        size = (low & 0xf0000000) | ((uint64_t)high << 32);
        if (addr < base || addr >= base + size) {
            continue;
        }

        ctrl = ldl_le_p(cache_mem + R_CXL_HDM_DECODER0_CTRL + i * hdm_inc);
        if (!FIELD_EX32(ctrl, CXL_HDM_DECODER0_CTRL, COMMITTED)) {
            return false;
        }
        found = true;
        ig_enc = FIELD_EX32(ctrl, CXL_HDM_DECODER0_CTRL, IG);
        iw_enc = FIELD_EX32(ctrl, CXL_HDM_DECODER0_CTRL, IW);
        target_idx = (addr / cxl_decode_ig(ig_enc)) % (1 << iw_enc);

        if (target_idx < 4) {
            uint32_t val = ldl_le_p(cache_mem +
                                    R_CXL_HDM_DECODER0_TARGET_LIST_LO +
                                    i * hdm_inc);
            *target = extract32(val, target_idx * 8, 8);
        } else {
            uint32_t val = ldl_le_p(cache_mem +
                                    R_CXL_HDM_DECODER0_TARGET_LIST_HI +
                                    i * hdm_inc);
            *target = extract32(val, (target_idx - 4) * 8, 8);
        }
        break;
    }

    return found;
}

static PCIDevice *cxl_cfmws_find_device(CXLFixedWindow *fw, hwaddr addr)
{
    CXLComponentState *hb_cstate, *usp_cstate;
    PCIHostState *hb;
    CXLUpstreamPort *usp;
    int rb_index;
    uint32_t *cache_mem;
    uint8_t target;
    bool target_found;
    PCIDevice *rp, *d;

    rb_index = (addr / cxl_decode_ig(fw->enc_int_gran)) % fw->num_targets;
    hb = PCI_HOST_BRIDGE(fw->target_hbs[rb_index]->cxl_host_bridge);
    if (!hb || !hb->bus || !pci_bus_is_cxl(hb->bus)) {
        return NULL;
    }

    if (cxl_get_hb_passthrough(hb)) {
        rp = pcie_find_port_first(hb->bus);
        if (!rp) {
            return NULL;
        }
    } else {
        hb_cstate = cxl_get_hb_cstate(hb);
        if (!hb_cstate) {
            return NULL;
        }

        cache_mem = hb_cstate->crb.cache_mem_registers;

        target_found = cxl_hdm_find_target(cache_mem, addr, &target);
        if (!target_found) {
            return NULL;
        }

        rp = pcie_find_port_by_pn(hb->bus, target);
        if (!rp) {
            return NULL;
        }
    }

    d = pci_bridge_get_sec_bus(PCI_BRIDGE(rp))->devices[0];
    if (!d) {
        return NULL;
    }

    if (object_dynamic_cast(OBJECT(d), TYPE_CXL_TYPE3)) {
        return d;
    }

    /*
     * Could also be a switch.  Note only one level of switching currently
     * supported.
     */
    if (!object_dynamic_cast(OBJECT(d), TYPE_CXL_USP)) {
        return NULL;
    }
    usp = CXL_USP(d);

    usp_cstate = cxl_usp_to_cstate(usp);
    if (!usp_cstate) {
        return NULL;
    }

    cache_mem = usp_cstate->crb.cache_mem_registers;

    target_found = cxl_hdm_find_target(cache_mem, addr, &target);
    if (!target_found) {
        return NULL;
    }

    d = pcie_find_port_by_pn(&PCI_BRIDGE(d)->sec_bus, target);
    if (!d) {
        return NULL;
    }

    d = pci_bridge_get_sec_bus(PCI_BRIDGE(d))->devices[0];
    if (!d) {
        return NULL;
    }

    if (!object_dynamic_cast(OBJECT(d), TYPE_CXL_TYPE3)) {
        return NULL;
    }

    return d;
}

static MemTxResult cxl_read_cfmws(void *opaque, hwaddr addr, uint64_t *data,
                                  unsigned size, MemTxAttrs attrs)
{
    CXLFixedWindow *fw = opaque;
    PCIDevice *d;

    d = cxl_cfmws_find_device(fw, addr + fw->base);
    if (d == NULL) {
        *data = 0;
        /* Reads to invalid address return poison */
        return MEMTX_ERROR;
    }

    return cxl_type3_read(d, addr + fw->base, data, size, attrs);
}

static MemTxResult cxl_write_cfmws(void *opaque, hwaddr addr,
                                   uint64_t data, unsigned size,
                                   MemTxAttrs attrs)
{
    CXLFixedWindow *fw = opaque;
    PCIDevice *d;

    d = cxl_cfmws_find_device(fw, addr + fw->base);
    if (d == NULL) {
        /* Writes to invalid address are silent */
        return MEMTX_OK;
    }

    return cxl_type3_write(d, addr + fw->base, data, size, attrs);
}

const MemoryRegionOps cfmws_ops = {
    .read_with_attrs = cxl_read_cfmws,
    .write_with_attrs = cxl_write_cfmws,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = true,
    },
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = true,
    },
};

static void machine_get_cxl(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    CXLState *cxl_state = opaque;
    bool value = cxl_state->is_enabled;

    visit_type_bool(v, name, &value, errp);
}

static void machine_set_cxl(Object *obj, Visitor *v, const char *name,
                            void *opaque, Error **errp)
{
    CXLState *cxl_state = opaque;
    bool value;

    if (!visit_type_bool(v, name, &value, errp)) {
        return;
    }
    cxl_state->is_enabled = value;
}

static void machine_get_cfmw(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    CXLState *state = opaque;
    CXLFixedMemoryWindowOptionsList **list = &state->cfmw_list;

    visit_type_CXLFixedMemoryWindowOptionsList(v, name, list, errp);
}

static void machine_set_cfmw(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    CXLState *state = opaque;
    CXLFixedMemoryWindowOptionsList *cfmw_list = NULL;
    CXLFixedMemoryWindowOptionsList *it;
    int index;

    visit_type_CXLFixedMemoryWindowOptionsList(v, name, &cfmw_list, errp);
    if (!cfmw_list) {
        return;
    }

    for (it = cfmw_list, index = 0; it; it = it->next, index++) {
        cxl_fixed_memory_window_config(it->value, index, errp);
    }
    state->cfmw_list = cfmw_list;
}

void cxl_machine_init(Object *obj, CXLState *state)
{
    qemu_log("cxl_machine_init called\n");
    object_property_add(obj, "cxl", "bool", machine_get_cxl,
                        machine_set_cxl, NULL, state);
    object_property_set_description(obj, "cxl",
                                    "Set on/off to enable/disable "
                                    "CXL instantiation");

    object_property_add(obj, "cxl-fmw", "CXLFixedMemoryWindow",
                        machine_get_cfmw, machine_set_cfmw,
                        NULL, state);
    object_property_set_description(obj, "cxl-fmw",
                                    "CXL Fixed Memory Windows (array)");
}

void cxl_hook_up_pxb_registers(PCIBus *bus, CXLState *state, Error **errp)
{
    /* Walk the pci busses looking for pxb busses to hook up */
    if (bus) {
        QLIST_FOREACH(bus, &bus->child, sibling) {
            if (!pci_bus_is_root(bus)) {
                continue;
            }
            if (pci_bus_is_cxl(bus)) {
                if (!state->is_enabled) {
                    error_setg(errp, "CXL host bridges present, but cxl=off");
                    return;
                }
                pxb_cxl_hook_up_registers(state, bus, errp);
            }
        }
    }
}

static int cxl_fmws_find(Object *obj, void *opaque)
{
    GSList **list = opaque;

    if (!object_dynamic_cast(obj, TYPE_CXL_FMW)) {
        return 0;
    }
    *list = g_slist_prepend(*list, obj);

    return 0;
}

static GSList *cxl_fmws_get_all(void)
{
    GSList *list = NULL;

    object_child_foreach_recursive(object_get_root(), cxl_fmws_find, &list);

    return list;
}

static gint cfmws_cmp(gconstpointer a, gconstpointer b, gpointer d)
{
    const struct CXLFixedWindow *ap = a;
    const struct CXLFixedWindow *bp = b;

    return ap->index > bp->index;
}

GSList *cxl_fmws_get_all_sorted(void)
{
    return g_slist_sort_with_data(cxl_fmws_get_all(), cfmws_cmp, NULL);
}

static int cxl_fmws_mmio_map(Object *obj, void *opaque)
{
    struct CXLFixedWindow *fw;

    if (!object_dynamic_cast(obj, TYPE_CXL_FMW)) {
        return 0;
    }
    fw = CXL_FMW(obj);
    sysbus_mmio_map(SYS_BUS_DEVICE(fw), 0, fw->base);
    qemu_log("cxl_fmws_mmio_map called %d %lx\n", fw->index, (unsigned long)fw->base);

    /* Print out all of the subregions for the fixed memory window */
    cxl_print_memory_region_hierarchy(&fw->mr, 0);

    return 0;
}

void cxl_fmws_update_mmio(void)
{
    /* Ordering is not required for this */
    object_child_foreach_recursive(object_get_root(), cxl_fmws_mmio_map, NULL);
}

hwaddr cxl_fmws_set_memmap(hwaddr base, hwaddr max_addr)
{
    GSList *cfmws_list, *iter;
    CXLFixedWindow *fw;

    qemu_log("cxl_fmws_set_memmap called base %lx max_addr %lx\n", base, max_addr);

    cfmws_list = cxl_fmws_get_all_sorted();
    for (iter = cfmws_list; iter; iter = iter->next) {
        fw = CXL_FMW(iter->data);
        if (base + fw->size <= max_addr) {
            fw->base = base;
            base += fw->size;
        }
    }
    g_slist_free(cfmws_list);

    return base;
}

static void cxl_fmw_realize(DeviceState *dev, Error **errp)
{
    CXLFixedWindow *fw = CXL_FMW(dev);

    qemu_log("cxl_fmw_realize called for index %d\n", fw->index);

    memory_region_init(&fw->mr, OBJECT(fw), "cxl-fixed-memory-region", fw->size);
    memory_region_init_io(&fw->base_mr, OBJECT(dev), &cfmws_ops, fw,
                          "cxl-fixed-memory-base-region", fw->size);
    memory_region_add_subregion_overlap(&fw->mr, 0, &fw->base_mr, -1);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &fw->mr);
}

/*
 * Note: Fixed memory windows represent fixed address decoders on the host and
 * as such have no dynamic state to reset or migrate
 */
static void cxl_fmw_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    qemu_log("cxl_fmw_class_init called\n");

    dc->desc = "CXL Fixed Memory Window";
    dc->realize = cxl_fmw_realize;
    /* Reason - created by machines as tightly coupled to machine memory map */
    dc->user_creatable = false;
}

static const TypeInfo cxl_fmw_info = {
    .name = TYPE_CXL_FMW,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(CXLFixedWindow),
    .class_init = cxl_fmw_class_init,
};

static void cxl_host_register_types(void)
{
    type_register_static(&cxl_fmw_info);
}
type_init(cxl_host_register_types)
