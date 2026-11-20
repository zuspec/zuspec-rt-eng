/*
 * pssvm_json.h -- the small JSON reader and writer the debug stub
 * (pssvm_stub.c) and the DPI server (pssvm_dpi.c) share. Internal: static
 * functions, included by the C files that use them.
 */
#ifndef PSSVM_JSON_H
#define PSSVM_JSON_H
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__)
#define PSSVM_JSON_UNUSED __attribute__((unused))
#else
#define PSSVM_JSON_UNUSED
#endif


enum { J_NULL, J_BOOL, J_INT, J_NUM, J_STR, J_ARR, J_OBJ };
typedef struct jv {
    int         t;
    int         b;
    int64_t     i;          /* J_INT (two's complement for > INT64_MAX) */
    char       *s;          /* J_STR */
    int         n;          /* J_ARR / J_OBJ */
    char      **k;          /* J_OBJ keys */
    struct jv  *v;          /* J_ARR / J_OBJ values */
    const char *raw;        /* the value's text */
    size_t      rawlen;
} jv;

static PSSVM_JSON_UNUSED void jfree(jv *x) {
    free(x->s);
    for (int j = 0; j < x->n; j++) {
        jfree(&x->v[j]);
        if (x->k) free(x->k[j]);
    }
    free(x->k); free(x->v);
    memset(x, 0, sizeof(*x));
}

static PSSVM_JSON_UNUSED void jws(const char **p) {
    while (**p == ' ' || **p == '\t' || **p == '\n' || **p == '\r') (*p)++;
}

static PSSVM_JSON_UNUSED int jparse(const char **p, jv *x, int depth);

static PSSVM_JSON_UNUSED char *jstring(const char **p) {
    const char *q = *p + 1;
    size_t cap = 16, n = 0;
    char *o = malloc(cap);
    for (;;) {
        unsigned c = (unsigned char)*q++;
        if (c == 0) { free(o); return NULL; }
        if (c == '"') break;
        if (n + 5 > cap) o = realloc(o, cap *= 2);
        if (c != '\\') { o[n++] = (char)c; continue; }
        c = (unsigned char)*q++;
        switch (c) {
        case 'n': o[n++] = '\n'; break;
        case 't': o[n++] = '\t'; break;
        case 'r': o[n++] = '\r'; break;
        case 'b': o[n++] = '\b'; break;
        case 'f': o[n++] = '\f'; break;
        case '"': case '\\': case '/': o[n++] = (char)c; break;
        case 'u': {
            unsigned u = 0;
            for (int j = 0; j < 4; j++, q++) {
                char h = *q;
                u <<= 4;
                if (h >= '0' && h <= '9') u |= (unsigned)(h - '0');
                else if (h >= 'a' && h <= 'f') u |= (unsigned)(h - 'a' + 10);
                else if (h >= 'A' && h <= 'F') u |= (unsigned)(h - 'A' + 10);
                else { free(o); return NULL; }
            }
            if (u < 0x80) o[n++] = (char)u;
            else if (u < 0x800) { o[n++] = (char)(0xC0 | (u >> 6)); o[n++] = (char)(0x80 | (u & 0x3F)); }
            else { o[n++] = (char)(0xE0 | (u >> 12)); o[n++] = (char)(0x80 | ((u >> 6) & 0x3F));
                   o[n++] = (char)(0x80 | (u & 0x3F)); }
            break;
        }
        default: free(o); return NULL;
        }
    }
    o[n] = 0;
    *p = q;
    return o;
}

static PSSVM_JSON_UNUSED int jparse(const char **p, jv *x, int depth) {
    memset(x, 0, sizeof(*x));
    if (depth > 64) return -1;
    jws(p);
    x->raw = *p;
    const char *q = *p;
    if (*q == '"') {
        x->t = J_STR;
        if ((x->s = jstring(p)) == NULL) return -1;
    } else if (*q == '{' || *q == '[') {
        int obj = *q == '{';
        x->t = obj ? J_OBJ : J_ARR;
        (*p)++; jws(p);
        if (**p == (obj ? '}' : ']')) { (*p)++; goto done; }
        int cap = 0;
        for (;;) {
            if (x->n == cap) {
                cap = cap ? 2 * cap : 4;
                x->v = realloc(x->v, (size_t)cap * sizeof(jv));
                if (obj) x->k = realloc(x->k, (size_t)cap * sizeof(char *));
            }
            if (obj) {
                jws(p);
                if (**p != '"') return -1;
                char *key = jstring(p);
                if (key == NULL) return -1;
                jws(p);
                if (**p != ':') { free(key); return -1; }
                x->k[x->n] = key;
                (*p)++;
            }
            int r = jparse(p, &x->v[x->n], depth + 1);
            x->n++;
            if (r) return -1;
            jws(p);
            if (**p == ',') { (*p)++; continue; }
            if (**p == (obj ? '}' : ']')) { (*p)++; break; }
            return -1;
        }
    } else if (!strncmp(q, "true", 4) || !strncmp(q, "false", 5)) {
        x->t = J_BOOL; x->b = *q == 't'; *p += x->b ? 4 : 5;
    } else if (!strncmp(q, "null", 4)) {
        x->t = J_NULL; *p += 4;
    } else if (*q == '-' || (*q >= '0' && *q <= '9')) {
        int neg = *q == '-';
        if (neg) q++;
        if (!(*q >= '0' && *q <= '9')) return -1;
        uint64_t u = 0;
        while (*q >= '0' && *q <= '9') u = u * 10 + (uint64_t)(*q++ - '0');
        x->t = J_INT;
        if (*q == '.' || *q == 'e' || *q == 'E') {
            x->t = J_NUM;
            q++;
            while ((*q >= '0' && *q <= '9') || *q == '+' || *q == '-' || *q == 'e' || *q == 'E') q++;
        }
        x->i = neg ? (int64_t)(0 - u) : (int64_t)u;
        *p = q;
    } else {
        return -1;
    }
done:
    x->rawlen = (size_t)(*p - x->raw);
    return 0;
}

static PSSVM_JSON_UNUSED jv *jget(jv *o, const char *key) {
    if (o == NULL || o->t != J_OBJ) return NULL;
    for (int j = 0; j < o->n; j++)
        if (!strcmp(o->k[j], key)) return &o->v[j];
    return NULL;
}
static PSSVM_JSON_UNUSED int jisint(const jv *x) { return x != NULL && x->t == J_INT; }

typedef struct { char *b; size_t n, cap; } sbuf;

static PSSVM_JSON_UNUSED void sb_put(sbuf *s, const char *t, size_t n) {
    if (s->n + n + 1 > s->cap) {
        while (s->n + n + 1 > s->cap) s->cap = s->cap ? 2 * s->cap : 256;
        s->b = realloc(s->b, s->cap);
    }
    memcpy(s->b + s->n, t, n);
    s->n += n;
    s->b[s->n] = 0;
}
static PSSVM_JSON_UNUSED void sb_f(sbuf *s, const char *fmt, ...) {
    char tmp[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n >= (int)sizeof(tmp)) n = sizeof(tmp) - 1;
    sb_put(s, tmp, (size_t)n);
}
static PSSVM_JSON_UNUSED void sb_str(sbuf *s, const char *t) {
    sb_put(s, "\"", 1);
    for (; t && *t; t++) {
        unsigned char c = (unsigned char)*t;
        if (c == '"' || c == '\\') { char e[2] = {'\\', (char)c}; sb_put(s, e, 2); }
        else if (c < 0x20) sb_f(s, "\\u%04x", c);
        else sb_put(s, (const char *)&c, 1);
    }
    sb_put(s, "\"", 1);
}

#endif /* PSSVM_JSON_H */
