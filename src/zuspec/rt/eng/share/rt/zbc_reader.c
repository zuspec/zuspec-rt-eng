/*
 * zbc_reader.c -- see zbc_reader.h.
 *
 * The .zbc layout is little-endian, naturally aligned, and the record structs in
 * zbc_format.h mirror it exactly (guarded by ZBC_STATIC_ASSERT there), so reading
 * is a bounds-checked cast. This host path assumes a little-endian host (the
 * big-endian swap path is a later concern [D§3a]).
 */
#include "zbc_reader.h"

static int in_bounds(const zbc_image_t *img, uint64_t off, uint64_t len) {
    return off <= img->size && len <= img->size && off + len <= img->size;
}

const zbc_section *zbc_find_section(const zbc_image_t *img, uint32_t kind) {
    for (uint32_t i = 0; i < img->section_count; i++) {
        if (img->sections[i].kind == kind) {
            return &img->sections[i];
        }
    }
    return NULL;
}

int zbc_image_open(zbc_image_t *img, const void *data, size_t size) {
    img->data = (const uint8_t *)data;
    img->size = size;
    img->code = NULL;  img->code_count = 0;
    img->coros = NULL; img->coro_count = 0;
    img->selects = NULL; img->select_count = 0;
    img->oplist = NULL;  img->oplist_count = 0;
    img->solves = NULL;  img->solve_count = 0;
    img->sprob = NULL;   img->sprob_count = 0;

    if (size < sizeof(zbc_header)) {
        return ZBC_ERR_TOO_SMALL;
    }
    const zbc_header *h = (const zbc_header *)data;
    img->hdr = h;

    if (h->magic[0] != ZBC_MAGIC0 || h->magic[1] != ZBC_MAGIC1 ||
        h->magic[2] != ZBC_MAGIC2 || h->magic[3] != ZBC_MAGIC3) {
        return ZBC_ERR_BAD_MAGIC;
    }
    if (h->version_major != ZBC_VERSION_MAJOR) {
        return ZBC_ERR_BAD_VERSION;    /* incompatible major -> reject */
    }
    if (h->abi_id != ZBC_ENGINE_ABI_ID) {
        return ZBC_ERR_BAD_ABI;
    }

    /* Section directory. */
    uint64_t dir_off = h->section_dir_off;
    uint64_t dir_len = (uint64_t)h->section_count * sizeof(zbc_section);
    if (!in_bounds(img, dir_off, dir_len)) {
        return ZBC_ERR_BAD_SECTIONS;
    }
    img->sections = (const zbc_section *)(img->data + dir_off);
    img->section_count = h->section_count;
    img->entry_coro = h->entry_coro;

    /* Resolve CODE + CORO (required for execution). */
    const zbc_section *code_sec = zbc_find_section(img, ZBC_SEC_CODE);
    if (!code_sec || !in_bounds(img, code_sec->offset, code_sec->size)) {
        return ZBC_ERR_NO_CODE;
    }
    img->code = (const zbc_instr *)(img->data + code_sec->offset);
    img->code_count = code_sec->count;

    const zbc_section *coro_sec = zbc_find_section(img, ZBC_SEC_CORO);
    if (!coro_sec || !in_bounds(img, coro_sec->offset, coro_sec->size)) {
        return ZBC_ERR_NO_CORO;
    }
    img->coros = (const zbc_coro *)(img->data + coro_sec->offset);
    img->coro_count = coro_sec->count;

    if (img->entry_coro >= img->coro_count) {
        return ZBC_ERR_BAD_ENTRY;
    }

    /* Optional OPLIST u32 pool -- shared by the SELECT and SOLVE tiers for their
     * variable-length operands (each descriptor records its own offset). Bound
     * independently so a SOLVE-only or SELECT-only image still resolves it. */
    const zbc_section *opl_sec = zbc_find_section(img, ZBC_SEC_OPLIST);
    if (opl_sec && in_bounds(img, opl_sec->offset, opl_sec->size)) {
        img->oplist = (const uint32_t *)(img->data + opl_sec->offset);
        img->oplist_count = opl_sec->count;
    }

    /* Optional SELECT descriptors (operands read from the OPLIST pool). Absent or
     * malformed -> NULL so a SELECT op reports ZBC_ERR_BAD_SELECT, not garbage. */
    const zbc_section *sel_sec = zbc_find_section(img, ZBC_SEC_SELECT);
    if (sel_sec && in_bounds(img, sel_sec->offset, sel_sec->size)) {
        img->selects = (const zbc_select *)(img->data + sel_sec->offset);
        img->select_count = sel_sec->count;
    }

    /* Optional SOLVE descriptors (writeback pairs read from the OPLIST pool). */
    const zbc_section *slv_sec = zbc_find_section(img, ZBC_SEC_SOLVE);
    if (slv_sec && in_bounds(img, slv_sec->offset, slv_sec->size)) {
        img->solves = (const zbc_solve *)(img->data + slv_sec->offset);
        img->solve_count = slv_sec->count;
    }

    /* Optional SPROB pool: raw relocatable dv-solve problem blobs. Bound independently
     * (a SOLVE with prob_len==0 uses the minimal randomizer and needs no pool). */
    const zbc_section *spr_sec = zbc_find_section(img, ZBC_SEC_SPROB);
    if (spr_sec && in_bounds(img, spr_sec->offset, spr_sec->size)) {
        img->sprob = img->data + spr_sec->offset;
        img->sprob_count = spr_sec->size;
    }
    return ZBC_OK;
}
