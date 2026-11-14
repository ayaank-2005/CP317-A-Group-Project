#include "report_status.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RS_FILE_HEADER "RSTORE 1"
#define RS_FIELD_COUNT 8

static const char *const STATUS_NAMES[] = {
    [RS_PENDING] = "Pending",
    [RS_APPROVED] = "Approved",
    [RS_REJECTED] = "Rejected",
    [RS_MERGED] = "Merged"
};

void rs_store_init(rs_store *store)
{
    store->items = NULL;
    store->count = 0;
    store->cap = 0;
}

void rs_store_free(rs_store *store)
{
    for (size_t i = 0; i < store->count; i++)
        free(store->items[i].content);
    free(store->items);
    rs_store_init(store);
}

rs_result rs_generate_id(char out[RS_ID_LEN + 1])
{
    unsigned char b[16];
    FILE *f = fopen("/dev/urandom", "rb");

    if (!f)
        return RS_ERR_RANDOM;
    size_t got = fread(b, 1, sizeof b, f);
    fclose(f);
    if (got != sizeof b)
        return RS_ERR_RANDOM;

    b[6] = (unsigned char)((b[6] & 0x0f) | 0x40); /* version 4 */
    b[8] = (unsigned char)((b[8] & 0x3f) | 0x80); /* RFC 4122 variant */

    snprintf(out, RS_ID_LEN + 1,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return RS_OK;
}

int rs_is_valid_id(const char *id)
{
    if (!id || strlen(id) != RS_ID_LEN)
        return 0;
    for (int i = 0; i < RS_ID_LEN; i++) {
        int dash = (i == 8 || i == 13 || i == 18 || i == 23);
        if (dash ? id[i] != '-' : !isxdigit((unsigned char)id[i]))
            return 0;
    }
    return 1;
}

/* User IDs are written to a tab-separated file and into HTML attributes. */
static int valid_user_id(const char *id, int allow_empty)
{
    size_t len = id ? strlen(id) : 0;

    if (len == 0)
        return allow_empty;
    if (len > RS_USER_ID_MAX)
        return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)id[i];
        if (!isalnum(c) && c != '-' && c != '_' && c != '.' && c != '@')
            return 0;
    }
    return 1;
}

static rs_report *find_mut(rs_store *store, const char *id)
{
    if (!id)
        return NULL;
    for (size_t i = 0; i < store->count; i++)
        if (strcmp(store->items[i].id, id) == 0)
            return &store->items[i];
    return NULL;
}

const rs_report *rs_find(const rs_store *store, const char *id)
{
    return find_mut((rs_store *)store, id);
}

static rs_result reserve(rs_store *store)
{
    if (store->count < store->cap)
        return RS_OK;

    size_t cap = store->cap ? store->cap * 2 : 16;
    rs_report *items = realloc(store->items, cap * sizeof *items);
    if (!items)
        return RS_ERR_NOMEM;
    store->items = items;
    store->cap = cap;
    return RS_OK;
}

rs_result rs_submit(rs_store *store, const char *submitter_id,
                    const char *content, time_t now,
                    char out_id[RS_ID_LEN + 1])
{
    if (!store || !content || !*content || strlen(content) > RS_CONTENT_MAX)
        return RS_ERR_ARG;
    if (!valid_user_id(submitter_id, 1))
        return RS_ERR_ARG;

    rs_result rc = reserve(store);
    if (rc != RS_OK)
        return rc;

    rs_report r;
    memset(&r, 0, sizeof r);

    /* A v4 collision is practically impossible, but the store must never
       hold duplicate IDs, so retry rather than trust it. */
    do {
        rc = rs_generate_id(r.id);
        if (rc != RS_OK)
            return rc;
    } while (find_mut(store, r.id));

    r.content = strdup(content);
    if (!r.content)
        return RS_ERR_NOMEM;
    if (submitter_id)
        strcpy(r.submitter_id, submitter_id);
    r.status = RS_PENDING;
    r.created_at = now;
    r.updated_at = now;

    store->items[store->count++] = r;
    if (out_id)
        strcpy(out_id, r.id);
    return RS_OK;
}

rs_result rs_decide(rs_store *store, const char *report_id,
                    const char *moderator_id, rs_role role,
                    rs_status decision, const char *merge_target_id,
                    time_t now)
{
    if (!store || !report_id)
        return RS_ERR_ARG;
    if (role != RS_ROLE_MODERATOR)
        return RS_ERR_FORBIDDEN;
    if (!valid_user_id(moderator_id, 0))
        return RS_ERR_ARG;
    if (decision != RS_APPROVED && decision != RS_REJECTED &&
        decision != RS_MERGED)
        return RS_ERR_TRANSITION;

    rs_report *r = find_mut(store, report_id);
    if (!r)
        return RS_ERR_NOT_FOUND;
    if (r->status != RS_PENDING)
        return RS_ERR_TRANSITION;

    if (decision == RS_MERGED) {
        /* Only Approved targets: they are final and public, so the
           merged report's link can never point at a hidden page. */
        const rs_report *target = find_mut(store, merge_target_id);
        if (!target || target == r || target->status != RS_APPROVED)
            return RS_ERR_MERGE_TARGET;
        strcpy(r->merged_into_id, target->id);
    }

    r->status = decision;
    strcpy(r->reviewed_by, moderator_id);
    r->updated_at = now;
    return RS_OK;
}

static int newest_first(const void *a, const void *b)
{
    const rs_report *ra = *(const rs_report *const *)a;
    const rs_report *rb = *(const rs_report *const *)b;

    if (ra->created_at != rb->created_at)
        return ra->created_at < rb->created_at ? 1 : -1;
    /* qsort is not stable; break ties by store order (later = newer). */
    return ra < rb ? 1 : (ra > rb ? -1 : 0);
}

const rs_report **rs_list_by_submitter(const rs_store *store,
                                       const char *submitter_id,
                                       size_t *out_count)
{
    *out_count = 0;
    if (!store || !submitter_id || !*submitter_id)
        return NULL;

    size_t n = 0;
    for (size_t i = 0; i < store->count; i++)
        if (strcmp(store->items[i].submitter_id, submitter_id) == 0)
            n++;
    if (n == 0)
        return NULL;

    const rs_report **list = malloc(n * sizeof *list);
    if (!list)
        return NULL;

    n = 0;
    for (size_t i = 0; i < store->count; i++)
        if (strcmp(store->items[i].submitter_id, submitter_id) == 0)
            list[n++] = &store->items[i];

    qsort(list, n, sizeof *list, newest_first);
    *out_count = n;
    return list;
}

int rs_public_url(const rs_report *report, char *buf, size_t len)
{
    const char *id;

    if (!report || !buf)
        return 0;
    if (report->status == RS_APPROVED)
        id = report->id;
    else if (report->status == RS_MERGED && report->merged_into_id[0])
        id = report->merged_into_id;
    else
        return 0;

    int n = snprintf(buf, len, "%s%s", RS_PUBLIC_REPORT_BASE, id);
    return n > 0 && (size_t)n < len;
}

const char *rs_status_name(rs_status status)
{
    if ((unsigned)status > RS_MERGED)
        return "Unknown";
    return STATUS_NAMES[status];
}

int rs_status_parse(const char *text, rs_status *out)
{
    if (!text)
        return 0;
    for (int s = RS_PENDING; s <= RS_MERGED; s++) {
        if (strcasecmp(text, STATUS_NAMES[s]) == 0) {
            *out = (rs_status)s;
            return 1;
        }
    }
    return 0;
}

int rs_role_parse(const char *text, rs_role *out)
{
    if (!text)
        return 0;
    if (strcmp(text, "user") == 0)
        *out = RS_ROLE_USER;
    else if (strcmp(text, "moderator") == 0)
        *out = RS_ROLE_MODERATOR;
    else if (strcmp(text, "analyst") == 0)
        *out = RS_ROLE_ANALYST;
    else
        return 0;
    return 1;
}

const char *rs_strerror(rs_result result)
{
    switch (result) {
    case RS_OK: return "ok";
    case RS_ERR_ARG: return "invalid argument";
    case RS_ERR_NOMEM: return "out of memory";
    case RS_ERR_NOT_FOUND: return "report not found";
    case RS_ERR_FORBIDDEN: return "only moderators can change a report's status";
    case RS_ERR_TRANSITION: return "only Pending reports can be approved, rejected or merged";
    case RS_ERR_MERGE_TARGET: return "merge target must be a different, Approved report";
    case RS_ERR_RANDOM: return "could not generate a report ID";
    case RS_ERR_IO: return "could not read or write the report store";
    case RS_ERR_FORMAT: return "report store file is malformed";
    }
    return "unknown error";
}

/* ---- Persistence: one tab-separated record per line ---- */

static void write_escaped(FILE *f, const char *s)
{
    for (; *s; s++) {
        switch (*s) {
        case '\\': fputs("\\\\", f); break;
        case '\t': fputs("\\t", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        default: fputc(*s, f);
        }
    }
}

/* Unescapes in place; returns 0 on a dangling or unknown escape. */
static int unescape(char *s)
{
    char *w = s;

    for (char *r = s; *r; r++) {
        if (*r != '\\') {
            *w++ = *r;
            continue;
        }
        switch (*++r) {
        case '\\': *w++ = '\\'; break;
        case 't': *w++ = '\t'; break;
        case 'n': *w++ = '\n'; break;
        case 'r': *w++ = '\r'; break;
        default: return 0;
        }
    }
    *w = '\0';
    return 1;
}

rs_result rs_save(const rs_store *store, const char *path)
{
    char tmp[4096];

    if (!store || !path)
        return RS_ERR_ARG;
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp)
        return RS_ERR_ARG;

    FILE *f = fopen(tmp, "w");
    if (!f)
        return RS_ERR_IO;

    fprintf(f, "%s\n", RS_FILE_HEADER);
    for (size_t i = 0; i < store->count; i++) {
        const rs_report *r = &store->items[i];
        fprintf(f, "%s\t%s\t%s\t%s\t%s\t%lld\t%lld\t",
                r->id, r->submitter_id, rs_status_name(r->status),
                r->merged_into_id, r->reviewed_by,
                (long long)r->created_at, (long long)r->updated_at);
        write_escaped(f, r->content);
        fputc('\n', f);
    }

    int failed = ferror(f);
    if (fclose(f) != 0 || failed) {
        remove(tmp);
        return RS_ERR_IO;
    }
    /* Rename so a crash mid-write never leaves a truncated store. */
    if (rename(tmp, path) != 0) {
        remove(tmp);
        return RS_ERR_IO;
    }
    return RS_OK;
}

static int parse_time(const char *s, time_t *out)
{
    char *end;

    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno || end == s || *end)
        return 0;
    *out = (time_t)v;
    return 1;
}

static rs_result parse_record(char *line, rs_report *r)
{
    char *field[RS_FIELD_COUNT];
    int n = 0;

    /* Split on every tab: empty fields (anonymous submitter, no merge
       target) are meaningful, so strtok's collapsing would be wrong. */
    field[n++] = line;
    for (char *p = line; *p && n < RS_FIELD_COUNT; p++) {
        if (*p == '\t') {
            *p = '\0';
            field[n++] = p + 1;
        }
    }
    if (n != RS_FIELD_COUNT)
        return RS_ERR_FORMAT;

    memset(r, 0, sizeof *r);
    if (!rs_is_valid_id(field[0]) || !valid_user_id(field[1], 1) ||
        !rs_status_parse(field[2], &r->status) ||
        !valid_user_id(field[4], 1) ||
        !parse_time(field[5], &r->created_at) ||
        !parse_time(field[6], &r->updated_at) || !unescape(field[7]))
        return RS_ERR_FORMAT;

    if (r->status == RS_MERGED ? !rs_is_valid_id(field[3]) : field[3][0] != '\0')
        return RS_ERR_FORMAT;

    strcpy(r->id, field[0]);
    strcpy(r->submitter_id, field[1]);
    strcpy(r->merged_into_id, field[3]);
    strcpy(r->reviewed_by, field[4]);
    r->content = strdup(field[7]);
    return r->content ? RS_OK : RS_ERR_NOMEM;
}

rs_result rs_load(rs_store *store, const char *path)
{
    if (!store || !path)
        return RS_ERR_ARG;

    rs_store loaded;
    rs_store_init(&loaded);

    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno != ENOENT)
            return RS_ERR_IO;
        rs_store_free(store);
        return RS_OK;
    }

    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    rs_result rc = RS_OK;
    int header = 1;

    while ((len = getline(&line, &cap, f)) != -1) {
        if (len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';

        if (header) {
            header = 0;
            if (strcmp(line, RS_FILE_HEADER) != 0) {
                rc = RS_ERR_FORMAT;
                break;
            }
            continue;
        }

        rs_report r;
        if ((rc = reserve(&loaded)) != RS_OK ||
            (rc = parse_record(line, &r)) != RS_OK)
            break;
        if (find_mut(&loaded, r.id)) {
            free(r.content);
            rc = RS_ERR_FORMAT;
            break;
        }
        loaded.items[loaded.count++] = r;
    }

    if (rc == RS_OK && ferror(f))
        rc = RS_ERR_IO;
    free(line);
    fclose(f);

    if (rc != RS_OK) {
        rs_store_free(&loaded);
        return rc;
    }
    rs_store_free(store);
    *store = loaded;
    return RS_OK;
}
