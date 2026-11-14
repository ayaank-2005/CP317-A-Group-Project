#include "my_reports.h"

#include <stdlib.h>
#include <string.h>

/* Placeholders inserted by redact.go, shown as masks like database.js does. */
static const char *const MASK_LABELS[] = {
    "[EMAIL]", "[PHONE]", "[CARD]", "[SIN]", "[ADDRESS]", "[POSTAL_CODE]", "[NAME]"
};

static const char *status_tag_class(rs_status status)
{
    switch (status) {
    case RS_APPROVED:
    case RS_MERGED: return "clean";
    case RS_REJECTED: return "malicious";
    default: return "unknown";
    }
}

static const char *status_explanation(rs_status status)
{
    switch (status) {
    case RS_APPROVED: return "A moderator approved this report. It is now public.";
    case RS_MERGED: return "A moderator combined this with an existing public report about the same scam.";
    case RS_REJECTED: return "A moderator reviewed this report and did not publish it.";
    default: return "Waiting for a moderator to review it.";
    }
}

static void html_escape_n(FILE *out, const char *s, size_t n)
{
    for (size_t i = 0; i < n && s[i]; i++) {
        switch (s[i]) {
        case '&': fputs("&amp;", out); break;
        case '<': fputs("&lt;", out); break;
        case '>': fputs("&gt;", out); break;
        case '"': fputs("&quot;", out); break;
        case '\'': fputs("&#39;", out); break;
        default: fputc(s[i], out);
        }
    }
}

static void html_escape(FILE *out, const char *s)
{
    html_escape_n(out, s, strlen(s));
}

/* Length of the preview, cut on a UTF-8 character boundary. */
static size_t preview_len(const char *s, int *truncated)
{
    size_t len = strlen(s);

    *truncated = len > MY_REPORTS_PREVIEW_LEN;
    if (!*truncated)
        return len;
    len = MY_REPORTS_PREVIEW_LEN;
    while (len > 0 && ((unsigned char)s[len] & 0xC0) == 0x80)
        len--;
    return len;
}

static void render_body(FILE *out, const char *s, size_t n)
{
    size_t i = 0, start = 0;

    while (i < n) {
        size_t label_len = 0;
        if (s[i] == '[') {
            for (size_t k = 0; k < sizeof MASK_LABELS / sizeof *MASK_LABELS; k++) {
                size_t l = strlen(MASK_LABELS[k]);
                if (i + l <= n && strncmp(s + i, MASK_LABELS[k], l) == 0) {
                    label_len = l;
                    break;
                }
            }
        }
        if (!label_len) {
            i++;
            continue;
        }
        html_escape_n(out, s + start, i - start);
        fputs("<span class=\"mask\" title=\"Personal detail hidden to protect privacy\">", out);
        html_escape_n(out, s + i, label_len);
        fputs("</span>", out);
        i += label_len;
        start = i;
    }
    html_escape_n(out, s + start, n - start);
}

static void format_date(char *buf, size_t len, time_t t)
{
    struct tm tm;

    if (!gmtime_r(&t, &tm) || !strftime(buf, len, "%b %d, %Y", &tm))
        snprintf(buf, len, "unknown date");
}

static void render_card(FILE *out, const rs_report *r)
{
    char submitted[32], updated[32], url[256];
    int truncated;
    size_t n = preview_len(r->content, &truncated);

    format_date(submitted, sizeof submitted, r->created_at);
    format_date(updated, sizeof updated, r->updated_at);

    fprintf(out, "      <article class=\"report\" id=\"report-%s\">\n", r->id);
    fprintf(out, "        <div class=\"report-head\">\n"
                 "          <span class=\"tag %s\">%s</span>\n"
                 "          <span class=\"sender\"><span class=\"sender-type\">Report ID</span>"
                 "<code>%s</code></span>\n"
                 "        </div>\n",
            status_tag_class(r->status), rs_status_name(r->status), r->id);

    fputs("        <p class=\"report-body\">", out);
    render_body(out, r->content, n);
    if (truncated)
        fputs("…", out);
    fputs("</p>\n", out);

    fprintf(out, "        <p class=\"hint flush\">%s</p>\n", status_explanation(r->status));

    fprintf(out, "        <p class=\"meta\">Submitted %s", submitted);
    if (r->status != RS_PENDING)
        fprintf(out, " · %s %s", rs_status_name(r->status), updated);
    fputs("</p>\n", out);

    if (rs_public_url(r, url, sizeof url)) {
        fputs("        <p class=\"meta\"><a href=\"", out);
        html_escape(out, url);
        fprintf(out, "\">%s</a></p>\n",
                r->status == RS_MERGED ? "View the public report it was merged into"
                                       : "View public report");
    }
    fputs("      </article>\n", out);
}

/* rs_list_by_submitter returns NULL both for "none" and for malloc failure. */
static int list_reports(const rs_store *store, const char *user_id,
                        const rs_report ***list, size_t *count)
{
    *list = rs_list_by_submitter(store, user_id, count);
    if (*list || !store || !user_id || !*user_id)
        return 0;
    for (size_t i = 0; i < store->count; i++)
        if (strcmp(store->items[i].submitter_id, user_id) == 0)
            return -1;
    return 0;
}

int my_reports_render_html(FILE *out, const rs_store *store,
                           const char *user_id)
{
    const rs_report **list;
    size_t count;

    if (list_reports(store, user_id, &list, &count) != 0)
        return -1;

    fputs("<!DOCTYPE html>\n"
          "<html lang=\"en\">\n"
          "<head>\n"
          "    <meta charset=\"UTF-8\">\n"
          "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\n"
          "    <title>My Reports – ScamShield</title>\n"
          "    <link rel=\"stylesheet\" href=\"Styling.css\">\n"
          "    <link rel=\"stylesheet\" href=\"database.css\">\n"
          "</head>\n"
          "<body>\n"
          "    <div class=\"wrap\">\n"
          "        <header class=\"top\">\n"
          "            <div class=\"brand\">Scam Shield</div>\n"
          "            <nav aria-label=\"Main\">\n"
          "                <a href=\"index.html#home\">Home</a>\n"
          "                <a href=\"index.html#database\">Database</a>\n"
          "                <a href=\"index.html#report\">Report</a>\n"
          "                <a href=\"my-reports.html\" aria-current=\"page\">My Reports</a>\n"
          "            </nav>\n"
          "        </header>\n"
          "\n"
          "        <main id=\"v-my-reports\">\n"
          "            <h1>My Reports</h1>\n"
          "            <p class=\"lede\">Track the scams you've reported. Approved and merged reports are public in the Scam Database.</p>\n",
          out);

    if (count == 0) {
        fputs("            <div class=\"state\">\n"
              "                <h2>You haven't reported any scams yet</h2>\n"
              "                <p>When you report a scam, it will appear here with its review status.</p>\n"
              "                <p><a href=\"index.html#report\">Report a scam</a></p>\n"
              "            </div>\n",
              out);
    } else {
        fprintf(out, "            <p class=\"db-status\" role=\"status\">%zu %s</p>\n",
                count, count == 1 ? "report" : "reports");
        fputs("            <div id=\"myReports\">\n", out);
        for (size_t i = 0; i < count; i++)
            render_card(out, list[i]);
        fputs("            </div>\n", out);
    }

    fputs("        </main>\n"
          "    </div>\n"
          "</body>\n"
          "</html>\n",
          out);

    free(list);
    return ferror(out) ? -1 : 0;
}

int my_reports_render_text(FILE *out, const rs_store *store,
                           const char *user_id)
{
    const rs_report **list;
    size_t count;
    char url[256], date[32];

    if (list_reports(store, user_id, &list, &count) != 0)
        return -1;
    if (count == 0) {
        fputs("You haven't reported any scams yet.\n", out);
        return ferror(out) ? -1 : 0;
    }

    for (size_t i = 0; i < count; i++) {
        const rs_report *r = list[i];
        format_date(date, sizeof date, r->created_at);
        fprintf(out, "%-8s  %s  submitted %s\n", rs_status_name(r->status), r->id, date);
        if (rs_public_url(r, url, sizeof url))
            fprintf(out, "          %s\n", url);
    }
    free(list);
    return ferror(out) ? -1 : 0;
}
