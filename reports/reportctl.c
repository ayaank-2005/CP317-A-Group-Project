/*
 * Command-line front end for report status tracking.
 *
 *   reportctl STORE submit USER_ID CONTENT
 *   reportctl STORE decide MODERATOR_ID ROLE REPORT_ID approve|reject|merge [TARGET_ID]
 *   reportctl STORE mine USER_ID [--html]
 */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "my_reports.h"
#include "report_status.h"

static int usage(const char *prog)
{
    fprintf(stderr,
            "usage:\n"
            "  %s STORE submit USER_ID CONTENT\n"
            "  %s STORE decide MODERATOR_ID ROLE REPORT_ID approve|reject|merge [TARGET_ID]\n"
            "  %s STORE mine USER_ID [--html]\n",
            prog, prog, prog);
    return 2;
}

static int fail(rs_result rc)
{
    fprintf(stderr, "error: %s\n", rs_strerror(rc));
    return 1;
}

static int parse_decision(const char *text, rs_status *out)
{
    if (strcmp(text, "approve") == 0)
        *out = RS_APPROVED;
    else if (strcmp(text, "reject") == 0)
        *out = RS_REJECTED;
    else if (strcmp(text, "merge") == 0)
        *out = RS_MERGED;
    else
        return 0;
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 4)
        return usage(argv[0]);

    const char *path = argv[1];
    const char *cmd = argv[2];
    rs_store store;
    rs_result rc;
    int status = 0;

    rs_store_init(&store);
    if ((rc = rs_load(&store, path)) != RS_OK)
        return fail(rc);

    if (strcmp(cmd, "submit") == 0 && argc == 5) {
        char id[RS_ID_LEN + 1];
        if ((rc = rs_submit(&store, argv[3], argv[4], time(NULL), id)) != RS_OK ||
            (rc = rs_save(&store, path)) != RS_OK)
            status = fail(rc);
        else
            printf("%s\n", id);
    } else if (strcmp(cmd, "decide") == 0 && (argc == 7 || argc == 8)) {
        rs_role role;
        rs_status decision;
        if (!rs_role_parse(argv[4], &role) || !parse_decision(argv[6], &decision)) {
            status = usage(argv[0]);
        } else if ((rc = rs_decide(&store, argv[5], argv[3], role, decision,
                                   argc == 8 ? argv[7] : NULL, time(NULL))) != RS_OK ||
                   (rc = rs_save(&store, path)) != RS_OK) {
            status = fail(rc);
        } else {
            printf("%s %s\n", argv[5], rs_status_name(rs_find(&store, argv[5])->status));
        }
    } else if (strcmp(cmd, "mine") == 0 && (argc == 4 || argc == 5)) {
        int html = argc == 5 && strcmp(argv[4], "--html") == 0;
        if (argc == 5 && !html)
            status = usage(argv[0]);
        else if ((html ? my_reports_render_html : my_reports_render_text)(stdout, &store, argv[3]) != 0)
            status = 1;
    } else {
        status = usage(argv[0]);
    }

    rs_store_free(&store);
    return status;
}
