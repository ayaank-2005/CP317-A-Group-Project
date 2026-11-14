#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../my_reports.h"
#include "../report_status.h"

static int failures;
static int checks;

#define CHECK(cond)                                                        \
    do {                                                                   \
        checks++;                                                          \
        if (!(cond)) {                                                     \
            failures++;                                                    \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,         \
                    __LINE__, #cond);                                      \
        }                                                                  \
    } while (0)

#define CHECK_RC(expr, want) CHECK((expr) == (want))

static char *render(int html, const rs_store *store, const char *user)
{
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);

    if (html)
        CHECK(my_reports_render_html(f, store, user) == 0);
    else
        CHECK(my_reports_render_text(f, store, user) == 0);
    fclose(f);
    return buf;
}

static void test_ids(void)
{
    char a[RS_ID_LEN + 1], b[RS_ID_LEN + 1];

    CHECK_RC(rs_generate_id(a), RS_OK);
    CHECK_RC(rs_generate_id(b), RS_OK);
    CHECK(rs_is_valid_id(a));
    CHECK(a[14] == '4');
    CHECK(strchr("89ab", a[19]) != NULL);
    CHECK(strcmp(a, b) != 0);
    CHECK(!rs_is_valid_id("not-an-id"));
    CHECK(!rs_is_valid_id("zzzzzzzz-zzzz-4zzz-8zzz-zzzzzzzzzzzz"));
}

static void test_submit(void)
{
    rs_store s;
    char id[RS_ID_LEN + 1];

    rs_store_init(&s);
    CHECK_RC(rs_submit(&s, "alice", "Fake CRA call", 100, id), RS_OK);
    const rs_report *r = rs_find(&s, id);
    CHECK(r != NULL);
    CHECK(r && r->status == RS_PENDING);
    CHECK(r && strcmp(r->submitter_id, "alice") == 0);
    CHECK(r && r->merged_into_id[0] == '\0');

    CHECK_RC(rs_submit(&s, NULL, "anonymous tip", 100, id), RS_OK);
    CHECK_RC(rs_submit(&s, "alice", "", 100, id), RS_ERR_ARG);
    CHECK_RC(rs_submit(&s, "bad\tuser", "x", 100, id), RS_ERR_ARG);
    CHECK_RC(rs_submit(&s, "<script>", "x", 100, id), RS_ERR_ARG);

    /* Many submissions: all IDs unique and the store grows correctly. */
    for (int i = 0; i < 200; i++)
        CHECK_RC(rs_submit(&s, "bulk", "spam", i, NULL), RS_OK);
    int dupes = 0;
    for (size_t i = 0; i < s.count; i++)
        for (size_t j = i + 1; j < s.count; j++)
            dupes += strcmp(s.items[i].id, s.items[j].id) == 0;
    CHECK(dupes == 0);
    CHECK(s.count == 202);

    rs_store_free(&s);
}

static void test_transitions(void)
{
    rs_store s;
    char a[RS_ID_LEN + 1], b[RS_ID_LEN + 1], c[RS_ID_LEN + 1], d[RS_ID_LEN + 1];

    rs_store_init(&s);
    rs_submit(&s, "alice", "A", 1, a);
    rs_submit(&s, "bob", "B", 2, b);
    rs_submit(&s, "alice", "C", 3, c);
    rs_submit(&s, "carol", "D", 4, d);

    /* Only moderators may decide. */
    CHECK_RC(rs_decide(&s, a, "alice", RS_ROLE_USER, RS_APPROVED, NULL, 10), RS_ERR_FORBIDDEN);
    CHECK_RC(rs_decide(&s, a, "ann", RS_ROLE_ANALYST, RS_APPROVED, NULL, 10), RS_ERR_FORBIDDEN);
    CHECK(rs_find(&s, a)->status == RS_PENDING);

    CHECK_RC(rs_decide(&s, a, "mod1", RS_ROLE_MODERATOR, RS_PENDING, NULL, 10), RS_ERR_TRANSITION);
    CHECK_RC(rs_decide(&s, "00000000-0000-4000-8000-000000000000", "mod1",
                       RS_ROLE_MODERATOR, RS_APPROVED, NULL, 10), RS_ERR_NOT_FOUND);

    CHECK_RC(rs_decide(&s, a, "mod1", RS_ROLE_MODERATOR, RS_APPROVED, NULL, 10), RS_OK);
    const rs_report *ra = rs_find(&s, a);
    CHECK(ra->status == RS_APPROVED);
    CHECK(strcmp(ra->reviewed_by, "mod1") == 0);
    CHECK(ra->updated_at == 10 && ra->created_at == 1);

    /* Decisions are final. */
    CHECK_RC(rs_decide(&s, a, "mod1", RS_ROLE_MODERATOR, RS_REJECTED, NULL, 11), RS_ERR_TRANSITION);

    CHECK_RC(rs_decide(&s, b, "mod1", RS_ROLE_MODERATOR, RS_REJECTED, NULL, 12), RS_OK);
    CHECK(rs_find(&s, b)->status == RS_REJECTED);

    /* Merge target must exist, differ, and be Approved. */
    CHECK_RC(rs_decide(&s, c, "mod1", RS_ROLE_MODERATOR, RS_MERGED, NULL, 13), RS_ERR_MERGE_TARGET);
    CHECK_RC(rs_decide(&s, c, "mod1", RS_ROLE_MODERATOR, RS_MERGED, c, 13), RS_ERR_MERGE_TARGET);
    CHECK_RC(rs_decide(&s, c, "mod1", RS_ROLE_MODERATOR, RS_MERGED, b, 13), RS_ERR_MERGE_TARGET);
    CHECK_RC(rs_decide(&s, c, "mod1", RS_ROLE_MODERATOR, RS_MERGED, d, 13), RS_ERR_MERGE_TARGET);
    CHECK(rs_find(&s, c)->status == RS_PENDING);

    CHECK_RC(rs_decide(&s, c, "mod1", RS_ROLE_MODERATOR, RS_MERGED, a, 13), RS_OK);
    CHECK(rs_find(&s, c)->status == RS_MERGED);
    CHECK(strcmp(rs_find(&s, c)->merged_into_id, a) == 0);

    rs_store_free(&s);
}

static void test_list_and_links(void)
{
    rs_store s;
    char a[RS_ID_LEN + 1], b[RS_ID_LEN + 1], c[RS_ID_LEN + 1], url[256];
    size_t n;

    rs_store_init(&s);
    rs_submit(&s, "alice", "first", 1, a);
    rs_submit(&s, "bob", "other", 2, b);
    rs_submit(&s, "alice", "second", 3, c);

    const rs_report **list = rs_list_by_submitter(&s, "alice", &n);
    CHECK(n == 2);
    CHECK(list && strcmp(list[0]->id, c) == 0); /* newest first */
    CHECK(list && strcmp(list[1]->id, a) == 0);
    free(list);

    CHECK(rs_list_by_submitter(&s, "nobody", &n) == NULL && n == 0);
    CHECK(rs_list_by_submitter(&s, "", &n) == NULL && n == 0);

    CHECK(!rs_public_url(rs_find(&s, a), url, sizeof url));

    rs_decide(&s, a, "mod1", RS_ROLE_MODERATOR, RS_APPROVED, NULL, 5);
    CHECK(rs_public_url(rs_find(&s, a), url, sizeof url));
    CHECK(strstr(url, a) != NULL);
    CHECK(strncmp(url, RS_PUBLIC_REPORT_BASE, strlen(RS_PUBLIC_REPORT_BASE)) == 0);

    rs_decide(&s, c, "mod1", RS_ROLE_MODERATOR, RS_MERGED, a, 6);
    CHECK(rs_public_url(rs_find(&s, c), url, sizeof url));
    CHECK(strstr(url, a) != NULL); /* links to the report it merged into */

    rs_decide(&s, b, "mod1", RS_ROLE_MODERATOR, RS_REJECTED, NULL, 7);
    CHECK(!rs_public_url(rs_find(&s, b), url, sizeof url));

    char tiny[8];
    CHECK(!rs_public_url(rs_find(&s, a), tiny, sizeof tiny));

    rs_store_free(&s);
}

static void test_persistence(void)
{
    char path[] = "/tmp/rs_test_XXXXXX";
    int fd = mkstemp(path);
    rs_store s, t;
    char a[RS_ID_LEN + 1], b[RS_ID_LEN + 1], c[RS_ID_LEN + 1];

    CHECK(fd >= 0);
    close(fd);
    remove(path);

    rs_store_init(&s);
    rs_store_init(&t);

    /* Missing file loads as empty. */
    CHECK_RC(rs_load(&t, path), RS_OK);
    CHECK(t.count == 0);

    rs_submit(&s, "alice", "line one\nline\ttwo \\ back", 1, a);
    rs_submit(&s, NULL, "anon", 2, b);
    rs_submit(&s, "alice", "dup", 3, c);
    rs_decide(&s, a, "mod1", RS_ROLE_MODERATOR, RS_APPROVED, NULL, 9);
    rs_decide(&s, c, "mod1", RS_ROLE_MODERATOR, RS_MERGED, a, 10);

    CHECK_RC(rs_save(&s, path), RS_OK);
    CHECK_RC(rs_load(&t, path), RS_OK);
    CHECK(t.count == 3);
    for (size_t i = 0; i < s.count && i < t.count; i++) {
        const rs_report *x = &s.items[i], *y = &t.items[i];
        CHECK(strcmp(x->id, y->id) == 0);
        CHECK(strcmp(x->submitter_id, y->submitter_id) == 0);
        CHECK(strcmp(x->content, y->content) == 0);
        CHECK(x->status == y->status);
        CHECK(strcmp(x->merged_into_id, y->merged_into_id) == 0);
        CHECK(strcmp(x->reviewed_by, y->reviewed_by) == 0);
        CHECK(x->created_at == y->created_at && x->updated_at == y->updated_at);
    }

    /* A corrupt file is rejected and leaves the store untouched. */
    FILE *f = fopen(path, "w");
    fputs("RSTORE 1\nnot\ta\tvalid\trecord\n", f);
    fclose(f);
    CHECK_RC(rs_load(&t, path), RS_ERR_FORMAT);
    CHECK(t.count == 3);

    f = fopen(path, "w");
    fputs("something else\n", f);
    fclose(f);
    CHECK_RC(rs_load(&t, path), RS_ERR_FORMAT);

    remove(path);
    rs_store_free(&s);
    rs_store_free(&t);
}

static void test_render(void)
{
    rs_store s;
    char a[RS_ID_LEN + 1], b[RS_ID_LEN + 1], c[RS_ID_LEN + 1], d[RS_ID_LEN + 1];

    rs_store_init(&s);
    rs_submit(&s, "alice", "Call from <b>CRA</b> & [PHONE] asked for gift cards", 1, a);
    rs_submit(&s, "alice", "Rejected one", 2, b);
    rs_submit(&s, "alice", "Merged one", 3, c);
    rs_submit(&s, "alice", "Still pending", 4, d);
    rs_submit(&s, "bob", "Bob's secret report", 5, NULL);
    rs_decide(&s, a, "mod1", RS_ROLE_MODERATOR, RS_APPROVED, NULL, 6);
    rs_decide(&s, b, "mod1", RS_ROLE_MODERATOR, RS_REJECTED, NULL, 7);
    rs_decide(&s, c, "mod1", RS_ROLE_MODERATOR, RS_MERGED, a, 8);

    char *html = render(1, &s, "alice");
    CHECK(strstr(html, "<h1>My Reports</h1>") != NULL);
    CHECK(strstr(html, "4 reports") != NULL);
    CHECK(strstr(html, "Bob") == NULL); /* only the user's own reports */
    CHECK(strstr(html, "<b>CRA</b>") == NULL); /* escaped */
    CHECK(strstr(html, "&lt;b&gt;CRA&lt;/b&gt; &amp;") != NULL);
    CHECK(strstr(html, "<span class=\"mask\"") != NULL);
    CHECK(strstr(html, "class=\"tag clean\">Approved") != NULL);
    CHECK(strstr(html, "class=\"tag malicious\">Rejected") != NULL);
    CHECK(strstr(html, "class=\"tag clean\">Merged") != NULL);
    CHECK(strstr(html, "class=\"tag unknown\">Pending") != NULL);

    /* Exactly two links to the public report: Approved and Merged. */
    char href[256];
    snprintf(href, sizeof href, "href=\"%s%s\"", RS_PUBLIC_REPORT_BASE, a);
    int links = 0;
    for (const char *p = html; (p = strstr(p, href)); p++)
        links++;
    CHECK(links == 2);
    snprintf(href, sizeof href, "%s%s", RS_PUBLIC_REPORT_BASE, b);
    CHECK(strstr(html, href) == NULL);
    snprintf(href, sizeof href, "%s%s", RS_PUBLIC_REPORT_BASE, d);
    CHECK(strstr(html, href) == NULL);
    free(html);

    html = render(1, &s, "nobody");
    CHECK(strstr(html, "You haven't reported any scams yet") != NULL);
    free(html);

    char *text = render(0, &s, "alice");
    CHECK(strstr(text, "Approved") && strstr(text, "Pending") &&
          strstr(text, "Rejected") && strstr(text, "Merged"));
    free(text);

    /* Long content is clamped to the preview length. */
    char longtext[1000];
    memset(longtext, 'x', sizeof longtext - 1);
    longtext[sizeof longtext - 1] = '\0';
    rs_submit(&s, "dave", longtext, 9, NULL);
    html = render(1, &s, "dave");
    CHECK(strstr(html, "…") != NULL);
    CHECK(strstr(html, longtext + 1000 - 1 - MY_REPORTS_PREVIEW_LEN - 1) == NULL);
    free(html);

    rs_store_free(&s);
}

static void test_names(void)
{
    rs_status st;
    rs_role role;

    CHECK(strcmp(rs_status_name(RS_MERGED), "Merged") == 0);
    CHECK(rs_status_parse("approved", &st) && st == RS_APPROVED);
    CHECK(!rs_status_parse("collecting", &st));
    CHECK(rs_role_parse("moderator", &role) && role == RS_ROLE_MODERATOR);
    CHECK(!rs_role_parse("admin", &role));
}

int main(void)
{
    test_ids();
    test_submit();
    test_transitions();
    test_list_and_links();
    test_persistence();
    test_render();
    test_names();

    if (failures) {
        fprintf(stderr, "%d of %d checks failed\n", failures, checks);
        return 1;
    }
    printf("All %d checks passed\n", checks);
    return 0;
}
