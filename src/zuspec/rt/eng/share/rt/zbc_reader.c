/*
 * zbc_reader.c -- see zbc_reader.h.
 *
 * The .zbc layout is little-endian, naturally aligned, and the record structs in
 * zbc_format.h mirror it exactly (guarded by ZBC_STATIC_ASSERT there), so reading
 * is a bounds-checked cast. This host path assumes a little-endian host (the
 * big-endian swap path is a later concern [D§3a]).
 */
#include "zbc_reader.h"
#include "zbc_ops.h"
#include <string.h>

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

/* Index the MSG section and check every index in it. */
static int open_msg(zbc_image_t *img, const zbc_section *sec) {
    if (sec->size < sizeof(zbc_msgtab) || !in_bounds(img, sec->offset, sec->size))
        return ZBC_ERR_BAD_SECTIONS;
    const uint8_t *p = img->data + sec->offset;
    const zbc_msgtab *t = (const zbc_msgtab *)p;
    uint64_t need = sizeof(zbc_msgtab) + (uint64_t)t->n_msgs * sizeof(zbc_msg)
        + (uint64_t)t->n_args * sizeof(zbc_msgarg) + (uint64_t)t->n_items * sizeof(zbc_msgitem)
        + 4ull * t->n_slots + 4ull * t->n_strings + t->strb_size;
    if (need > sec->size || t->n_model_strings > t->n_strings
            || (t->strb_size && p[need - 1] != 0) || (t->n_strings && !t->strb_size))
        return ZBC_ERR_BAD_SECTIONS;
    uint64_t off = sizeof(zbc_msgtab);
    img->msgs = (const zbc_msg *)(p + off);         off += (uint64_t)t->n_msgs * sizeof(zbc_msg);
    img->msgargs = (const zbc_msgarg *)(p + off);   off += (uint64_t)t->n_args * sizeof(zbc_msgarg);
    img->msgitems = (const zbc_msgitem *)(p + off); off += (uint64_t)t->n_items * sizeof(zbc_msgitem);
    img->msgslots = (const uint32_t *)(p + off);    off += 4ull * t->n_slots;
    img->msgstr_off = (const uint32_t *)(p + off);  off += 4ull * t->n_strings;
    img->msgstrb = (const char *)(p + off);
    for (uint32_t i = 0; i < t->n_strings; i++)
        if (img->msgstr_off[i] >= t->strb_size) return ZBC_ERR_BAD_SECTIONS;
    for (uint32_t i = 0; i < t->n_msgs; i++) {
        const zbc_msg *m = &img->msgs[i];
        if (m->fmt >= t->n_strings || (uint64_t)m->arg0 + m->n_args > t->n_args
                || (uint64_t)m->slot0 + m->n_args + 1 > t->n_slots)
            return ZBC_ERR_BAD_SECTIONS;
    }
    for (uint32_t i = 0; i < t->n_args; i++) {
        const zbc_msgarg *a = &img->msgargs[i];
        if (a->kind > ZBC_MSG_FLOAT || (uint64_t)a->item0 + a->n_items > t->n_items)
            return ZBC_ERR_BAD_SECTIONS;
    }
    for (uint32_t i = 0; i < t->n_items; i++)
        if (img->msgitems[i].name >= t->n_strings) return ZBC_ERR_BAD_SECTIONS;
    img->msgtab = t;
    return ZBC_OK;
}

#define ACT_NONE 0xFFFFFFFFu
/* first + n lies within a run of `total` (no overflow). */
#define RANGE(first, n, total) ((uint64_t)(first) + (n) <= (uint64_t)(total))
/* An optional local id: ACT_NONE or below `n`. */
#define OPT(x, n) ((x) == ACT_NONE || (x) < (n))

/* Index the ACT section (P4.10c2) and check every range and id in it, so
 * the engine can follow an activation's nodes, sites and writes unchecked.
 * Needs CORO (coro_count) parsed first. */
static int open_act(zbc_image_t *img, const zbc_section *sec) {
    if (sec->size < sizeof(zbc_acttab) || !in_bounds(img, sec->offset, sec->size))
        return ZBC_ERR_BAD_SECTIONS;
    const uint8_t *p = img->data + sec->offset;
    const zbc_acttab *t = (const zbc_acttab *)p;
    uint64_t need = sizeof(zbc_acttab) + (uint64_t)t->n_init * sizeof(zbc_actinit)
        + (uint64_t)t->n_acts * sizeof(zbc_act) + (uint64_t)t->n_nodes * sizeof(zbc_actnode)
        + (uint64_t)t->n_scopes * sizeof(zbc_actscope) + (uint64_t)t->n_sites * sizeof(zbc_actsite)
        + (uint64_t)t->n_cones * sizeof(zbc_actcone) + (uint64_t)t->n_vars * sizeof(zbc_actvar)
        + (uint64_t)t->n_cons * sizeof(zbc_actcon) + (uint64_t)t->n_pools * sizeof(zbc_actpool)
        + (uint64_t)t->n_claims * sizeof(zbc_actclaim) + (uint64_t)t->n_writes * sizeof(zbc_actwrite)
        + (uint64_t)t->n_picks * sizeof(zbc_actpick) + 4ull * t->n_u32 + 4ull * t->n_strings;
    uint64_t text = need;
    need += (uint64_t)t->strb_size + t->blob_size;
    if (need > sec->size || (t->n_strings && (!t->strb_size || p[text + t->strb_size - 1] != 0)))
        return ZBC_ERR_BAD_SECTIONS;
    uint64_t off = sizeof(zbc_acttab);
    img->actinits = (const zbc_actinit *)(p + off);   off += (uint64_t)t->n_init * sizeof(zbc_actinit);
    img->acts = (const zbc_act *)(p + off);            off += (uint64_t)t->n_acts * sizeof(zbc_act);
    img->actnodes = (const zbc_actnode *)(p + off);    off += (uint64_t)t->n_nodes * sizeof(zbc_actnode);
    img->actscopes = (const zbc_actscope *)(p + off);  off += (uint64_t)t->n_scopes * sizeof(zbc_actscope);
    img->actsites = (const zbc_actsite *)(p + off);    off += (uint64_t)t->n_sites * sizeof(zbc_actsite);
    img->actcones = (const zbc_actcone *)(p + off);    off += (uint64_t)t->n_cones * sizeof(zbc_actcone);
    img->actvars = (const zbc_actvar *)(p + off);      off += (uint64_t)t->n_vars * sizeof(zbc_actvar);
    img->actcons = (const zbc_actcon *)(p + off);      off += (uint64_t)t->n_cons * sizeof(zbc_actcon);
    img->actpools = (const zbc_actpool *)(p + off);    off += (uint64_t)t->n_pools * sizeof(zbc_actpool);
    img->actclaims = (const zbc_actclaim *)(p + off);  off += (uint64_t)t->n_claims * sizeof(zbc_actclaim);
    img->actwrites = (const zbc_actwrite *)(p + off);  off += (uint64_t)t->n_writes * sizeof(zbc_actwrite);
    img->actpicks = (const zbc_actpick *)(p + off);    off += (uint64_t)t->n_picks * sizeof(zbc_actpick);
    img->actlist = (const uint32_t *)(p + off);        off += 4ull * t->n_u32;
    img->actstr_off = (const uint32_t *)(p + off);     off += 4ull * t->n_strings;
    img->actstrb = (const char *)(p + off);            off += t->strb_size;
    img->actblob = p + off;
    const uint32_t ns = t->n_strings, nu = t->n_u32;
    for (uint32_t i = 0; i < ns; i++)
        if (img->actstr_off[i] >= t->strb_size) return ZBC_ERR_BAD_SECTIONS;
    for (uint32_t i = 0; i < t->n_writes; i++) {
        const zbc_actwrite *w = &img->actwrites[i];
        if (w->ref >= ns || !RANGE(w->src0, w->n_src, nu) || !RANGE(w->pool0, 2ull * w->n_pools, nu))
            return ZBC_ERR_BAD_SECTIONS;
    }
    for (uint32_t i = 0; i < t->n_claims; i++) {
        const zbc_actclaim *c = &img->actclaims[i];
        if (c->ref >= ns || !RANGE(c->pool0, 2ull * c->n_pools, nu)) return ZBC_ERR_BAD_SECTIONS;
    }
    for (uint32_t i = 0; i < t->n_picks; i++) {
        const zbc_actpick *k = &img->actpicks[i];
        if (k->ref >= ns || !RANGE(k->slot0, k->n_slots, nu) || !RANGE(k->pool0, 2ull * k->n_pools, nu))
            return ZBC_ERR_BAD_SECTIONS;
    }
    for (uint32_t i = 0; i < t->n_cons; i++) {
        const zbc_actcon *k = &img->actcons[i];
        if (k->text >= ns || !RANGE(k->node0, k->n_nodes, nu) || !RANGE(k->blob_off, k->blob_size, t->blob_size))
            return ZBC_ERR_BAD_SECTIONS;
    }
    for (uint32_t i = 0; i < t->n_vars; i++)
        if (img->actvars[i].name >= ns) return ZBC_ERR_BAD_SECTIONS;
    for (uint32_t i = 0; i < t->n_pools; i++) {
        const zbc_actpool *r = &img->actpools[i];
        if (r->name >= ns || r->kind >= ns || !RANGE(r->slot0, r->n_slots, nu)
                || !RANGE(r->leaf0, r->n_leaves, nu) || !RANGE(r->init0, r->n_init, nu))
            return ZBC_ERR_BAD_SECTIONS;
    }
    for (uint32_t a = 0; a < t->n_acts; a++) {
        const zbc_act *r = &img->acts[a];
        if (r->coro >= img->coro_count || r->root >= ns || r->type >= ns
                || !RANGE(r->node0, r->n_nodes, t->n_nodes) || !RANGE(r->scope0, r->n_scopes, t->n_scopes)
                || !RANGE(r->site0, r->n_sites, t->n_sites) || !RANGE(r->cone0, r->n_cones, t->n_cones)
                || !RANGE(r->pool0, r->n_pools, t->n_pools) || !RANGE(r->names0, r->n_names, nu)
                || !RANGE(r->init0, r->n_init, t->n_init))
            return ZBC_ERR_BAD_SECTIONS;
        for (uint32_t i = 0; i < r->n_names; i++)
            if (img->actlist[r->names0 + i] >= ns) return ZBC_ERR_BAD_SECTIONS;
        for (uint32_t i = 0; i < r->n_init; i++)
            if (img->actinits[r->init0 + i].slot >= r->size) return ZBC_ERR_BAD_SECTIONS;
        for (uint32_t i = 0; i < r->n_nodes; i++) {
            const zbc_actnode *n = &img->actnodes[r->node0 + i];
            if (n->path >= ns || n->type >= ns || (uint64_t)n->base + n->size > r->size
                    || !OPT(n->parent, r->n_nodes) || !OPT(n->decl_scope, r->n_scopes)
                    || !RANGE(n->comp0, n->n_comp, nu) || !RANGE(n->child0, n->n_children, nu)
                    || !RANGE(n->claim0, n->n_claims, t->n_claims)
                    || !RANGE(n->swrite0, n->n_swrites, t->n_writes)
                    || !RANGE(n->bwrite0, n->n_bwrites, t->n_writes)
                    || !RANGE(n->pick0, n->n_picks, t->n_picks))
                return ZBC_ERR_BAD_SECTIONS;
            for (uint32_t j = 0; j < n->n_children; j++)
                if (img->actlist[n->child0 + j] >= r->n_nodes) return ZBC_ERR_BAD_SECTIONS;
        }
        for (uint32_t i = 0; i < r->n_scopes; i++) {
            const zbc_actscope *c = &img->actscopes[r->scope0 + i];
            if (!OPT(c->parent, r->n_scopes) || c->node >= r->n_nodes) return ZBC_ERR_BAD_SECTIONS;
        }
        for (uint32_t i = 0; i < r->n_sites; i++) {
            const zbc_actsite *c = &img->actsites[r->site0 + i];
            if (c->owner >= r->n_nodes || c->target >= r->n_nodes || !OPT(c->scope, r->n_scopes))
                return ZBC_ERR_BAD_SECTIONS;
        }
        for (uint32_t i = 0; i < r->n_cones; i++) {
            const zbc_actcone *c = &img->actcones[r->cone0 + i];
            if (!RANGE(c->node0, c->n_nodes, nu) || !RANGE(c->var0, c->n_vars, t->n_vars)
                    || !RANGE(c->con0, c->n_cons, t->n_cons)
                    || !RANGE(c->base_off, c->base_size, t->blob_size))
                return ZBC_ERR_BAD_SECTIONS;
            for (uint32_t j = 0; j < c->n_nodes; j++)
                if (img->actlist[c->node0 + j] >= r->n_nodes) return ZBC_ERR_BAD_SECTIONS;
            for (uint32_t j = 0; j < c->n_vars; j++) {
                const zbc_actvar *v = &img->actvars[c->var0 + j];
                if (v->node >= r->n_nodes || v->slot >= r->size
                        || !OPT(v->loop_node, r->n_nodes) || !OPT(v->live_from, r->size))
                    return ZBC_ERR_BAD_SECTIONS;
                /* A loop index: its (coro, frame slot) pairs (P4.10f3). */
                if (v->loop_local != 0xFFFFFFFFu) {
                    if (v->loop_node == 0xFFFFFFFFu || v->loop0 >= nu
                            || !RANGE(v->loop0 + 1, 2u * (uint64_t)img->actlist[v->loop0], nu))
                        return ZBC_ERR_BAD_SECTIONS;
                    for (uint32_t m = 0; m < img->actlist[v->loop0]; m++)
                        if (img->actlist[v->loop0 + 1 + 2 * m] >= img->coro_count)
                            return ZBC_ERR_BAD_SECTIONS;
                }
            }
            for (uint32_t j = 0; j < c->n_cons; j++) {
                const zbc_actcon *k = &img->actcons[c->con0 + j];
                if (k->owner >= r->n_nodes || !OPT(k->scope, r->n_scopes) || !OPT(k->site, r->n_sites))
                    return ZBC_ERR_BAD_SECTIONS;
                for (uint32_t m = 0; m < k->n_nodes; m++)
                    if (img->actlist[k->node0 + m] >= r->n_nodes) return ZBC_ERR_BAD_SECTIONS;
            }
        }
    }
    img->acttab = t;
    return ZBC_OK;
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
    img->strb = NULL; img->strb_size = 0; img->stro = NULL; img->str_count = 0;
    img->entries = NULL; img->entry_count = 0; img->ident = NULL;
    img->imports = NULL; img->import_count = 0;
    img->comp = NULL;    img->comp_bases = NULL; img->cobj = NULL;
    img->msgtab = NULL;  img->msgs = NULL;  img->msgargs = NULL;
    img->msgitems = NULL; img->msgslots = NULL; img->msgstr_off = NULL; img->msgstrb = NULL;
    img->regs = NULL;    img->reg_count = 0; img->chans = NULL; img->chan_count = 0;
    img->execs = NULL;   img->exec_count = 0;
    img->events = NULL;  img->event_count = 0;
    img->covs = NULL;    img->cov_count = 0;
    img->locals = NULL;  img->local_count = 0;
    img->spin_stuck = NULL;
    img->acttab = NULL;  img->acts = NULL;   img->actnodes = NULL;  img->actscopes = NULL;
    img->actsites = NULL; img->actwrites = NULL;
    img->actlist = NULL; img->actstr_off = NULL; img->actstrb = NULL; img->actblob = NULL;

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
    if (h->flags & ZBC_HDR_EXT_MASK & ~(uint32_t)ZBC_ENGINE_EXTENSIONS) {
        return ZBC_ERR_BAD_PROFILE;    /* an extension this engine lacks */
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

    /* Optional COMP: one zbc_comp, then its n_inst u32 instance bases. */
    const zbc_section *cmp_sec = zbc_find_section(img, ZBC_SEC_COMP);
    if (cmp_sec) {
        const zbc_comp *c = (const zbc_comp *)(img->data + cmp_sec->offset);
        if (cmp_sec->size < sizeof(zbc_comp)
                || !in_bounds(img, cmp_sec->offset, cmp_sec->size)
                || cmp_sec->size < sizeof(zbc_comp) + 4ull * c->n_inst) {
            return ZBC_ERR_BAD_SECTIONS;
        }
        img->comp = c;
        img->comp_bases = (const uint32_t *)(img->data + cmp_sec->offset + sizeof(zbc_comp));
    }

    /* Optional MSG: zbc_msgtab, then its arrays (see zbc_msgtab). */
    const zbc_section *msg_sec = zbc_find_section(img, ZBC_SEC_MSG);
    if (msg_sec) {
        int rc = open_msg(img, msg_sec);
        if (rc != ZBC_OK) return rc;
    }

    /* Optional string table: STRO is str_count + 1 offsets into STRB, each
     * string NUL-terminated before the next offset. */
    const zbc_section *strb_sec = zbc_find_section(img, ZBC_SEC_STRB);
    const zbc_section *stro_sec = zbc_find_section(img, ZBC_SEC_STRO);
    if (strb_sec && stro_sec) {
        if (!in_bounds(img, strb_sec->offset, strb_sec->size)
                || !in_bounds(img, stro_sec->offset, stro_sec->size)
                || stro_sec->size < 4 || (stro_sec->size & 3)) {
            return ZBC_ERR_BAD_SECTIONS;
        }
        const char *b = (const char *)(img->data + strb_sec->offset);
        const uint32_t *o = (const uint32_t *)(img->data + stro_sec->offset);
        uint32_t n = (uint32_t)(stro_sec->size / 4) - 1;
        for (uint32_t i = 0; i < n; i++) {
            if (o[i] >= o[i + 1] || o[i + 1] > strb_sec->size || b[o[i + 1] - 1] != 0) {
                return ZBC_ERR_BAD_SECTIONS;
            }
        }
        img->strb = b;
        img->strb_size = (uint32_t)strb_sec->size;
        img->stro = o;
        img->str_count = n;
    }

    /* Optional ENTRY: zbc_entry[], whose names and signatures need the
     * string table. */
    const zbc_section *ent_sec = zbc_find_section(img, ZBC_SEC_ENTRY);
    if (ent_sec && ent_sec->count) {
        if (img->strb == NULL || !in_bounds(img, ent_sec->offset, ent_sec->size)
                || ent_sec->size < (uint64_t)ent_sec->count * sizeof(zbc_entry)) {
            return ZBC_ERR_BAD_SECTIONS;
        }
        const zbc_entry *e = (const zbc_entry *)(img->data + ent_sec->offset);
        for (uint32_t i = 0; i < ent_sec->count; i++) {
            if (e[i].name >= img->str_count || e[i].comp_type >= img->str_count
                    || e[i].sig >= img->str_count || e[i].coro >= img->coro_count) {
                return ZBC_ERR_BAD_SECTIONS;
            }
        }
        img->entries = e;
        img->entry_count = ent_sec->count;
    }

    /* Optional IMPORT: zbc_impent[] sorted by fn_id, names in the string
     * table. */
    const zbc_section *imp_sec = zbc_find_section(img, ZBC_SEC_IMPORT);
    if (imp_sec && imp_sec->count) {
        if (img->strb == NULL || !in_bounds(img, imp_sec->offset, imp_sec->size)
                || imp_sec->size < (uint64_t)imp_sec->count * sizeof(zbc_impent)) {
            return ZBC_ERR_BAD_SECTIONS;
        }
        const zbc_impent *m = (const zbc_impent *)(img->data + imp_sec->offset);
        for (uint32_t i = 0; i < imp_sec->count; i++) {
            if (m[i].name >= img->str_count || (i && m[i].fn_id <= m[i - 1].fn_id)) {
                return ZBC_ERR_BAD_SECTIONS;
            }
        }
        img->imports = m;
        img->import_count = imp_sec->count;
    }

    /* Optional IDENT: one zbc_ident. */
    const zbc_section *id_sec = zbc_find_section(img, ZBC_SEC_IDENT);
    if (id_sec) {
        /* 16 bytes: an image from before time_exp (F5.7) */
        if (id_sec->size < 16 || !in_bounds(img, id_sec->offset, id_sec->size)) {
            return ZBC_ERR_BAD_SECTIONS;
        }
        img->ident = (const zbc_ident *)(img->data + id_sec->offset);
        img->ident_size = id_sec->size;
    }

    /* Optional REG and CHAN (debug side tables): sorted by pc, pcs in CODE,
     * CHAN's names in the string table. */
    const zbc_section *reg_sec = zbc_find_section(img, ZBC_SEC_REG);
    if (reg_sec && reg_sec->count) {
        if (!in_bounds(img, reg_sec->offset, reg_sec->size)
                || reg_sec->size < (uint64_t)reg_sec->count * sizeof(zbc_regent)) {
            return ZBC_ERR_BAD_SECTIONS;
        }
        const zbc_regent *r = (const zbc_regent *)(img->data + reg_sec->offset);
        for (uint32_t i = 0; i < reg_sec->count; i++) {
            if (r[i].pc >= img->code_count || (i && r[i].pc <= r[i - 1].pc))
                return ZBC_ERR_BAD_SECTIONS;
        }
        img->regs = r;
        img->reg_count = reg_sec->count;
    }
    const zbc_section *exec_sec = zbc_find_section(img, ZBC_SEC_EXEC);
    if (exec_sec && exec_sec->size) {
        if (img->strb == NULL || !in_bounds(img, exec_sec->offset, exec_sec->size)
                || exec_sec->size < sizeof(zbc_exectab))
            return ZBC_ERR_BAD_SECTIONS;
        const zbc_exectab *t = (const zbc_exectab *)(img->data + exec_sec->offset);
        if (exec_sec->size < sizeof(zbc_exectab) + (uint64_t)t->n_exec * sizeof(zbc_execent))
            return ZBC_ERR_BAD_SECTIONS;
        const zbc_execent *x = (const zbc_execent *)(t + 1);
        for (uint32_t i = 0; i < t->n_exec; i++) {
            if (x[i].path >= img->str_count || x[i].type >= img->str_count
                    || x[i].trait >= img->str_count)
                return ZBC_ERR_BAD_SECTIONS;
        }
        img->execs = x;
        img->exec_count = t->n_exec;
    }
    const zbc_section *evt_sec = zbc_find_section(img, ZBC_SEC_EVENT);
    if (evt_sec && evt_sec->count) {
        if (img->strb == NULL || !in_bounds(img, evt_sec->offset, evt_sec->size)
                || evt_sec->size < (uint64_t)evt_sec->count * sizeof(zbc_evtent))
            return ZBC_ERR_BAD_SECTIONS;
        const zbc_evtent *v = (const zbc_evtent *)(img->data + evt_sec->offset);
        for (uint32_t i = 0; i < evt_sec->count; i++) {
            if (v[i].path >= img->str_count)
                return ZBC_ERR_BAD_SECTIONS;
        }
        img->events = v;
        img->event_count = evt_sec->count;
    }
    const zbc_section *chan_sec = zbc_find_section(img, ZBC_SEC_CHAN);
    if (chan_sec && chan_sec->count) {
        if (img->strb == NULL || !in_bounds(img, chan_sec->offset, chan_sec->size)
                || chan_sec->size < (uint64_t)chan_sec->count * sizeof(zbc_chanent)) {
            return ZBC_ERR_BAD_SECTIONS;
        }
        const zbc_chanent *c = (const zbc_chanent *)(img->data + chan_sec->offset);
        for (uint32_t i = 0; i < chan_sec->count; i++) {
            if (c[i].pc >= img->code_count || (i && c[i].pc <= c[i - 1].pc)
                    || c[i].channel >= img->str_count || c[i].op >= img->str_count)
                return ZBC_ERR_BAD_SECTIONS;
        }
        img->chans = c;
        img->chan_count = chan_sec->count;
    }
    const zbc_section *cov_sec = zbc_find_section(img, ZBC_SEC_COV);
    if (cov_sec && cov_sec->count) {
        if (img->strb == NULL || !in_bounds(img, cov_sec->offset, cov_sec->size)
                || cov_sec->size < (uint64_t)cov_sec->count * sizeof(zbc_covent)) {
            return ZBC_ERR_BAD_SECTIONS;
        }
        const zbc_covent *v = (const zbc_covent *)(img->data + cov_sec->offset);
        for (uint32_t i = 0; i < cov_sec->count; i++) {
            if (v[i].pc >= img->code_count || (i && v[i].pc < v[i - 1].pc)
                    || v[i].scope >= img->str_count || v[i].path >= img->str_count)
                return ZBC_ERR_BAD_SECTIONS;
        }
        img->covs = v;
        img->cov_count = cov_sec->count;
    }

    /* Optional statement starts (LINE flagged LINE_STMT): sorted by pc. */
    const zbc_section *line_sec = zbc_find_section(img, ZBC_SEC_LINE);
    if (line_sec && line_sec->count && (line_sec->flags & ZBC_SECF_LINE_STMT)) {
        if (!in_bounds(img, line_sec->offset, line_sec->size)
                || line_sec->size < (uint64_t)line_sec->count * sizeof(zbc_lineent)) {
            return ZBC_ERR_BAD_SECTIONS;
        }
        const zbc_lineent *l = (const zbc_lineent *)(img->data + line_sec->offset);
        for (uint32_t i = 0; i < line_sec->count; i++) {
            if (l[i].pc_start >= img->code_count
                    || (i && l[i].pc_start < l[i - 1].pc_start))
                return ZBC_ERR_BAD_SECTIONS;
        }
        img->stmts = l;
        img->stmt_count = line_sec->count;
    }

    /* Optional named locals (LOCAL): grouped by coro (a reader scans them). */
    const zbc_section *local_sec = zbc_find_section(img, ZBC_SEC_LOCAL);
    if (local_sec && local_sec->count) {
        if (img->strb == NULL || !in_bounds(img, local_sec->offset, local_sec->size)
                || local_sec->size < (uint64_t)local_sec->count * sizeof(zbc_localent)) {
            return ZBC_ERR_BAD_SECTIONS;
        }
        const zbc_localent *v = (const zbc_localent *)(img->data + local_sec->offset);
        for (uint32_t i = 0; i < local_sec->count; i++) {
            if (v[i].coro >= img->coro_count || v[i].name >= img->str_count
                    || v[i].pc_start > v[i].pc_end || v[i].pc_end > img->code_count
                    || (i && v[i].coro < v[i - 1].coro))
                return ZBC_ERR_BAD_SECTIONS;
        }
        img->locals = v;
        img->local_count = local_sec->count;
    }

    /* Optional FILE and PROV (provenance): paths in the string table, each
     * record's FileId in FILE (0 when there is none). */
    const zbc_section *file_sec = zbc_find_section(img, ZBC_SEC_FILE);
    if (file_sec && file_sec->count) {
        if (img->strb == NULL || !in_bounds(img, file_sec->offset, file_sec->size)
                || file_sec->size < (uint64_t)file_sec->count * sizeof(zbc_file)) {
            return ZBC_ERR_BAD_SECTIONS;
        }
        const zbc_file *f = (const zbc_file *)(img->data + file_sec->offset);
        for (uint32_t i = 0; i < file_sec->count; i++) {
            if (f[i].path >= img->str_count) return ZBC_ERR_BAD_SECTIONS;
        }
        img->files = f;
        img->file_count = file_sec->count;
    }
    const zbc_section *prov_sec = zbc_find_section(img, ZBC_SEC_PROV);
    if (prov_sec && prov_sec->count) {
        if (!in_bounds(img, prov_sec->offset, prov_sec->size)
                || prov_sec->size < (uint64_t)prov_sec->count * sizeof(zbc_prov)) {
            return ZBC_ERR_BAD_SECTIONS;
        }
        const zbc_prov *p = (const zbc_prov *)(img->data + prov_sec->offset);
        for (uint32_t i = 0; i < prov_sec->count; i++) {
            if (p[i].file && p[i].file >= img->file_count) return ZBC_ERR_BAD_SECTIONS;
        }
        img->provs = p;
        img->prov_count = prov_sec->count;
    }
    const zbc_section *sk_sec = zbc_find_section(img, ZBC_SEC_SEEDKEY);
    if (sk_sec && sk_sec->count) {
        if (sk_sec->count != img->coro_count || !in_bounds(img, sk_sec->offset, sk_sec->size)
                || sk_sec->size < 8ull * sk_sec->count || (sk_sec->offset & 7u)) {
            return ZBC_ERR_BAD_SECTIONS;
        }
        img->seed_keys = (const uint64_t *)(img->data + sk_sec->offset);
    }
    const zbc_section *act_sec = zbc_find_section(img, ZBC_SEC_ACT);
    if (act_sec) {
        int rc = open_act(img, act_sec);
        if (rc != ZBC_OK) return rc;
    }
    return ZBC_OK;
}

const zbc_act *zbc_image_act(const zbc_image_t *img, uint32_t coro) {
    if (!img->acttab) return NULL;
    for (uint32_t i = 0; i < img->acttab->n_acts; i++)
        if (img->acts[i].coro == coro) return &img->acts[i];
    return NULL;
}

const zbc_actnode *zbc_act_node(const zbc_image_t *img, const zbc_act *a, uint32_t id) {
    return &img->actnodes[a->node0 + id];
}

const zbc_actscope *zbc_act_scope(const zbc_image_t *img, const zbc_act *a, uint32_t id) {
    return &img->actscopes[a->scope0 + id];
}

const zbc_actsite *zbc_act_site(const zbc_image_t *img, const zbc_act *a, uint32_t id) {
    return &img->actsites[a->site0 + id];
}

const zbc_actcone *zbc_act_cone(const zbc_image_t *img, const zbc_act *a, uint32_t id) {
    return &img->actcones[a->cone0 + id];
}

const zbc_actvar *zbc_act_var(const zbc_image_t *img, uint32_t i) {
    return &img->actvars[i];
}

const zbc_actcon *zbc_act_con(const zbc_image_t *img, uint32_t i) {
    return &img->actcons[i];
}

const uint8_t *zbc_act_blob(const zbc_image_t *img, uint32_t off) {
    return img->actblob + off;
}

const zbc_actinit *zbc_act_init(const zbc_image_t *img, const zbc_act *a, uint32_t slot) {
    for (uint32_t i = 0; i < a->n_init; i++)
        if (img->actinits[a->init0 + i].slot == slot) return &img->actinits[a->init0 + i];
    return NULL;
}

const zbc_actwrite *zbc_act_write(const zbc_image_t *img, uint32_t i) {
    return &img->actwrites[i];
}

const uint32_t *zbc_act_list(const zbc_image_t *img, uint32_t i) {
    return &img->actlist[i];
}

const char *zbc_image_act_str(const zbc_image_t *img, uint32_t sid) {
    if (!img->acttab || sid >= img->acttab->n_strings) return NULL;
    return img->actstrb + img->actstr_off[sid];
}

const char *zbc_image_meta(const zbc_image_t *img, const char *name) {
    const zbc_section *sec = zbc_find_section(img, ZBC_SEC_META);
    if (sec == NULL || name == NULL || img->strb == NULL || !in_bounds(img, sec->offset, sec->size)
            || sec->size < (uint64_t)sec->count * sizeof(zbc_metaent)) {
        return NULL;
    }
    const zbc_metaent *m = (const zbc_metaent *)(img->data + sec->offset);
    for (uint32_t i = 0; i < sec->count; i++) {
        const char *nm = zbc_image_str(img, m[i].name);
        if (nm && !strcmp(nm, name)) return zbc_image_str(img, m[i].text);
    }
    return NULL;
}

static const zbc_impent *import_row(const zbc_image_t *img, uint32_t fn_id) {
    uint32_t lo = 0, hi = img->import_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (img->imports[mid].fn_id < fn_id) lo = mid + 1;
        else hi = mid;
    }
    return (lo < img->import_count && img->imports[lo].fn_id == fn_id)
           ? &img->imports[lo] : NULL;
}

const char *zbc_image_import_name(const zbc_image_t *img, uint32_t fn_id) {
    const zbc_impent *r = import_row(img, fn_id);
    return r ? zbc_image_str(img, r->name) : NULL;
}

uint32_t zbc_image_import_api(const zbc_image_t *img, uint32_t fn_id, uint32_t dflt) {
    const zbc_impent *r = import_row(img, fn_id);
    return r && r->api != 0xFFFFFFFFu ? r->api : dflt;   /* ~0: no API row */
}

const zbc_regent *zbc_image_reg_at(const zbc_image_t *img, uint32_t pc) {
    uint32_t lo = 0, hi = img->reg_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (img->regs[mid].pc < pc) lo = mid + 1;
        else hi = mid;
    }
    return (lo < img->reg_count && img->regs[lo].pc == pc) ? &img->regs[lo] : NULL;
}

const zbc_chanent *zbc_image_chan_at(const zbc_image_t *img, uint32_t pc) {
    uint32_t lo = 0, hi = img->chan_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (img->chans[mid].pc < pc) lo = mid + 1;
        else hi = mid;
    }
    return (lo < img->chan_count && img->chans[lo].pc == pc) ? &img->chans[lo] : NULL;
}

const zbc_lineent *zbc_image_stmts_at(const zbc_image_t *img, uint32_t pc, uint32_t *n) {
    uint32_t lo = 0, hi = img->stmt_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (img->stmts[mid].pc_start < pc) lo = mid + 1;
        else hi = mid;
    }
    uint32_t k = lo;
    while (k < img->stmt_count && img->stmts[k].pc_start == pc) k++;
    *n = k - lo;
    return k > lo ? &img->stmts[lo] : NULL;
}

const zbc_prov *zbc_image_prov(const zbc_image_t *img, uint32_t src_ref) {
    return (src_ref && src_ref < img->prov_count) ? &img->provs[src_ref] : NULL;
}

const char *zbc_image_file(const zbc_image_t *img, uint32_t file) {
    if (file == 0 || file >= img->file_count) return NULL;
    return zbc_image_str(img, img->files[file].path);
}

uint32_t zbc_image_src_ref(const zbc_image_t *img, uint32_t coro, uint32_t pc) {
    uint32_t sr = pc < img->code_count ? img->code[pc].src_ref : 0;
    if (sr == 0 && coro < img->coro_count) sr = img->coros[coro].src_ref;
    return sr;
}

const char *zbc_image_str(const zbc_image_t *img, uint32_t sid) {
    if (img->strb == NULL || sid >= img->str_count) return NULL;
    return img->strb + img->stro[sid];
}

const zbc_covent *zbc_image_cov_at(const zbc_image_t *img, uint32_t pc, int arm) {
    uint32_t lo = 0, hi = img->cov_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (img->covs[mid].pc < pc) lo = mid + 1;
        else hi = mid;
    }
    const zbc_covent *found = NULL;
    for (; lo < img->cov_count && img->covs[lo].pc == pc; lo++) {
        if (((img->covs[lo].flags & ZBC_COV_F_ARM) != 0) == (arm != 0))
            found = &img->covs[lo];
    }
    return found;
}
