/*
 * Report status tracking (UI-6-T1).
 *
 * Every submitted report gets a unique ID (UUID v4, same format as the
 * UUID primary keys in ScamShield_DB.sql) and a status that only a
 * moderator can change:
 *
 *   Pending --approve--> Approved
 *   Pending --reject---> Rejected
 *   Pending --merge----> Merged   (into an Approved report)
 *
 * Approved, Rejected and Merged are final. "Pending" covers both the
 * 'collecting' and 'pending_review' states of scam_reports.status.
 */
#ifndef REPORT_STATUS_H
#define REPORT_STATUS_H

#include <stddef.h>
#include <time.h>

#define RS_ID_LEN 36       /* xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx */
#define RS_USER_ID_MAX 64
#define RS_CONTENT_MAX 4000

/* Public reports live in the Database view of the single-page app. */
#ifndef RS_PUBLIC_REPORT_BASE
#define RS_PUBLIC_REPORT_BASE "index.html#database?report="
#endif

typedef enum {
    RS_PENDING = 0,
    RS_APPROVED,
    RS_REJECTED,
    RS_MERGED
} rs_status;

/* Mirrors users.role in ScamShield_DB.sql. */
typedef enum {
    RS_ROLE_USER = 0,
    RS_ROLE_MODERATOR,
    RS_ROLE_ANALYST
} rs_role;

typedef enum {
    RS_OK = 0,
    RS_ERR_ARG,
    RS_ERR_NOMEM,
    RS_ERR_NOT_FOUND,
    RS_ERR_FORBIDDEN,
    RS_ERR_TRANSITION,
    RS_ERR_MERGE_TARGET,
    RS_ERR_RANDOM,
    RS_ERR_IO,
    RS_ERR_FORMAT
} rs_result;

typedef struct {
    char id[RS_ID_LEN + 1];
    char submitter_id[RS_USER_ID_MAX + 1]; /* "" = anonymous */
    char *content;                         /* already-redacted text */
    rs_status status;
    char merged_into_id[RS_ID_LEN + 1];    /* set only when RS_MERGED */
    char reviewed_by[RS_USER_ID_MAX + 1];  /* moderator who decided */
    time_t created_at;
    time_t updated_at;
} rs_report;

typedef struct {
    rs_report *items;
    size_t count;
    size_t cap;
} rs_store;

void rs_store_init(rs_store *store);
void rs_store_free(rs_store *store);

/* Writes a fresh random UUID v4 into out. */
rs_result rs_generate_id(char out[RS_ID_LEN + 1]);
int rs_is_valid_id(const char *id);

/*
 * Adds a Pending report and copies its new ID into out_id (may be NULL).
 * submitter_id may be NULL or "" for anonymous submissions.
 */
rs_result rs_submit(rs_store *store, const char *submitter_id,
                    const char *content, time_t now,
                    char out_id[RS_ID_LEN + 1]);

/* Pointers returned by the store are invalidated by rs_submit/rs_load. */
const rs_report *rs_find(const rs_store *store, const char *id);

/*
 * Applies a moderator decision. merge_target_id is required for RS_MERGED
 * and must name a different, Approved report; it is ignored otherwise.
 */
rs_result rs_decide(rs_store *store, const char *report_id,
                    const char *moderator_id, rs_role role,
                    rs_status decision, const char *merge_target_id,
                    time_t now);

/*
 * Returns a malloc'd array of the user's reports, newest first, and its
 * length in *out_count. Returns NULL with *out_count == 0 when there are
 * none (or for an anonymous user). Caller frees the array only.
 */
const rs_report **rs_list_by_submitter(const rs_store *store,
                                       const char *submitter_id,
                                       size_t *out_count);

/*
 * Writes the public URL for an Approved report (its own page) or a Merged
 * report (the page it was merged into). Returns 1 if a link exists, 0 for
 * Pending/Rejected reports or if buf is too small.
 */
int rs_public_url(const rs_report *report, char *buf, size_t len);

rs_result rs_save(const rs_store *store, const char *path);
/* Replaces the store contents. A missing file loads as an empty store. */
rs_result rs_load(rs_store *store, const char *path);

const char *rs_status_name(rs_status status);
int rs_status_parse(const char *text, rs_status *out);
int rs_role_parse(const char *text, rs_role *out);
const char *rs_strerror(rs_result result);

#endif
