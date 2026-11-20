/*
 * zbc_fmt.c -- PSS string formatting (LRM 21.1.1) for message()/error()/
 * fatal(), the C twin of zuspec-be-bc interp/fmt.py `format_message`: the
 * same output for the same entry and values, or an error where it raises.
 */
#include <string.h>
#include "zbc_interp.h"

typedef struct { char *p; uint32_t n, cap; } buf_t;

static void put(buf_t *b, const char *s, uint32_t n) {
    for (uint32_t i = 0; i < n && b->n + 1 < b->cap; i++) b->p[b->n++] = s[i];
}

static void put_rep(buf_t *b, char c, int n) {
    for (; n > 0; n--) put(b, &c, 1);
}

typedef struct {
    const char *flags; uint32_t n_flags;
    int width;          /* -1: none */
    int prec;           /* -1: none */
    char conv;
} spec_t;

static int has(const spec_t *s, char f) {
    return memchr(s->flags, f, s->n_flags) != NULL;
}

/* Pad `s` (n bytes) to the spec's width: left-justified with '-'. */
static void pad(buf_t *b, const spec_t *sp, const char *s, uint32_t n) {
    int fill = sp->width > (int)n ? sp->width - (int)n : 0;
    if (!has(sp, '-')) put_rep(b, ' ', fill);
    put(b, s, n);
    if (has(sp, '-')) put_rep(b, ' ', fill);
}

static void render_int(buf_t *b, const spec_t *sp, uint64_t v, uint32_t width) {
    if (width < 1) width = 1;
    if (width > 64) width = 64;
    uint64_t mask = width == 64 ? ~(uint64_t)0 : (((uint64_t)1 << width) - 1);
    v &= mask;
    int neg = 0;
    uint64_t mag = v;
    if (sp->conv == 'd' && (v >> (width - 1)) & 1) {
        neg = 1;
        mag = (~v + 1) & mask;
        if (mag == 0) mag = (uint64_t)1 << (width - 1);    /* the most negative */
    }
    unsigned base = sp->conv == 'x' || sp->conv == 'X' ? 16
                  : sp->conv == 'o' ? 8 : sp->conv == 'b' || sp->conv == 'B' ? 2 : 10;
    const char *dig = sp->conv == 'X' ? "0123456789ABCDEF" : "0123456789abcdef";
    char tmp[64], *d = tmp + sizeof(tmp);
    uint64_t m = mag;
    do { *--d = dig[m % base]; m /= base; } while (m);
    int nd = (int)(tmp + sizeof(tmp) - d);
    if (sp->prec == 0 && mag == 0) nd = 0;
    int zeros = sp->prec > nd ? sp->prec - nd : 0;
    const char *prefix = "";
    if (has(sp, '#') && mag != 0) {
        switch (sp->conv) {
        case 'o': prefix = "0"; break;
        case 'x': prefix = "0x"; break;
        case 'X': prefix = "0X"; break;
        case 'b': prefix = "0b"; break;
        case 'B': prefix = "0B"; break;
        }
    }
    const char *sign = neg ? "-" : sp->conv != 'd' ? ""
                     : has(sp, '+') ? "+" : has(sp, ' ') ? " " : "";
    int body = (int)strlen(prefix) + zeros + nd, lead = 0;
    if (sp->width > 0 && has(sp, '0') && !has(sp, '-') && sp->prec < 0) {
        /* as fmt.py's (prefix + digits).rjust(width - len(sign), "0"):
         * the zeros go before the prefix */
        int w = sp->width - (int)strlen(sign);
        if (body < w) { lead = w - body; body = w; }
    }
    /* sign, lead zeros, prefix, precision zeros, digits; padded as text */
    int total = (int)strlen(sign) + body;
    int fill = sp->width > total ? sp->width - total : 0;
    if (!has(sp, '-')) put_rep(b, ' ', fill);
    put(b, sign, (uint32_t)strlen(sign));
    put_rep(b, '0', lead);
    put(b, prefix, (uint32_t)strlen(prefix));
    put_rep(b, '0', zeros);
    put(b, d, (uint32_t)nd);
    if (has(sp, '-')) put_rep(b, ' ', fill);
}

static void render_text(buf_t *b, const spec_t *sp, const char *s) {
    uint32_t n = (uint32_t)strlen(s);
    if (sp->prec >= 0 && (uint32_t)sp->prec < n) n = (uint32_t)sp->prec;
    pad(b, sp, s, n);
}

/* Parse the specifier at fmt[i] == '%'. Returns the index past it, or -1. */
static int parse_spec(const char *fmt, int i, spec_t *sp) {
    int j = i + 1;
    sp->flags = fmt + j;
    while (fmt[j] && strchr("-+ #0", fmt[j])) j++;
    sp->n_flags = (uint32_t)(fmt + j - sp->flags);
    sp->width = -1;
    if (fmt[j] >= '0' && fmt[j] <= '9') {
        sp->width = 0;
        while (fmt[j] >= '0' && fmt[j] <= '9') sp->width = sp->width * 10 + (fmt[j++] - '0');
    }
    sp->prec = -1;
    if (fmt[j] == '.') {
        j++;
        sp->prec = 0;
        while (fmt[j] >= '0' && fmt[j] <= '9') sp->prec = sp->prec * 10 + (fmt[j++] - '0');
    }
    if (!fmt[j] || !strchr("duxXobBns%", fmt[j])) return -1;
    sp->conv = fmt[j];
    if (sp->conv == '%' && (sp->n_flags || sp->width >= 0 || sp->prec >= 0)) return -1;
    return j + 1;
}

int zbc_format_message(const zbc_image_t *img, uint32_t msg_idx,
                       const uint64_t *locals, char *out, uint32_t cap,
                       uint64_t *level) {
    const zbc_msgtab *t = img->msgtab;
    if (!t || msg_idx >= t->n_msgs || cap == 0) return -1;
    const zbc_msg *m = &img->msgs[msg_idx];
    for (uint32_t k = 0; k <= m->n_args; k++)
        if (img->msgslots[m->slot0 + k] >= ZBC_MAX_LOCALS) return -1;
    *level = locals[img->msgslots[m->slot0]];
    const char *fmt = img->msgstrb + img->msgstr_off[m->fmt];
    buf_t b = { out, 0, cap };
    uint32_t arg = 0;
    for (int i = 0; fmt[i];) {
        if (fmt[i] != '%') { put(&b, &fmt[i++], 1); continue; }
        spec_t sp;
        int next = parse_spec(fmt, i, &sp);
        if (next < 0) return -1;
        i = next;
        if (sp.conv == '%') { put(&b, "%", 1); continue; }
        if (arg >= m->n_args) return -1;
        const zbc_msgarg *a = &img->msgargs[m->arg0 + arg];
        uint64_t v = locals[img->msgslots[m->slot0 + 1 + arg]];
        arg++;
        if (strchr("duxXobB", sp.conv)) {
            if (a->kind == ZBC_MSG_STRING) return -1;
            if (a->kind == ZBC_MSG_BOOL) render_int(&b, &sp, v ? 1 : 0, 32);
            else render_int(&b, &sp, v, a->width);
        } else if (sp.conv == 'n') {
            if (a->kind == ZBC_MSG_BOOL) {
                render_text(&b, &sp, v ? "true" : "false");
            } else if (a->kind == ZBC_MSG_ENUM) {
                uint32_t w = a->width < 1 ? 1 : a->width > 64 ? 64 : a->width;
                int64_t val = w == 64 ? (int64_t)v
                    : (int64_t)(v << (64 - w)) >> (64 - w);
                const char *name = NULL;
                for (uint32_t k = 0; k < a->n_items && !name; k++) {
                    const zbc_msgitem *it = &img->msgitems[a->item0 + k];
                    if ((int64_t)it->value == val) name = img->msgstrb + img->msgstr_off[it->name];
                }
                if (!name) return -1;
                render_text(&b, &sp, name);
            } else {
                return -1;
            }
        } else {                                   /* 's' */
            if (a->kind != ZBC_MSG_STRING || v >= t->n_model_strings) return -1;
            render_text(&b, &sp, img->msgstrb + img->msgstr_off[v]);
        }
    }
    if (arg != m->n_args) return -1;
    out[b.n] = 0;
    return (int)b.n;
}
