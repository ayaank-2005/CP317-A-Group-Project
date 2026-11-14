/*
 * "My Reports" page: a signed-in user's own reports and their statuses.
 * Approved and Merged reports link to the public report.
 */
#ifndef MY_REPORTS_H
#define MY_REPORTS_H

#include <stdio.h>

#include "report_status.h"

/* Same preview length as the Public Scam Database cards (database.js). */
#define MY_REPORTS_PREVIEW_LEN 220

/*
 * Writes a complete HTML page styled with Styling.css / database.css.
 * Returns 0 on success, -1 on a write or allocation failure.
 */
int my_reports_render_html(FILE *out, const rs_store *store,
                           const char *user_id);

/* Plain-text version of the same list for the command line. */
int my_reports_render_text(FILE *out, const rs_store *store,
                           const char *user_id);

#endif
