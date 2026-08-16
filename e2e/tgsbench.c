/* tgsbench — multithreaded TGS-REQ load generator for the e2e suite.
 *
 * kvno-based load tops out benchmarking fork/exec and FILE-ccache
 * re-parsing instead of the KDC. This keeps N threads hot on
 * krb5_get_credentials(KRB5_GC_NO_STORE): every call is a full TGS-REQ
 * on the wire, nothing is written back to the ccache.
 *
 * usage: tgsbench <ccname> <threads> <reqs-per-thread> <nhosts> [ip:A.B]
 * Default service names: host/h%04u.example.com (e2e realm). With the
 * optional ip:A.B arg, names are host/A.(B + n/65536).(n>>8 & 255).(n & 255)
 * over n in [0, nhosts) — matches the burn-test dataset of /16s of
 * host/1.2.3.4-style principals.
 * output: "ok=<n> err=<n>" on stdout; exit 1 if any request failed.
 */
#include <krb5.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *ccname;
static int per_thread, nhosts;
static int ip_mode, ip_b1, ip_b2;
static atomic_long n_ok, n_err;

static void service_name(char *buf, size_t len, unsigned n)
{
    if (ip_mode)
        snprintf(buf, len, "host/%d.%u.%u.%u", ip_b1,
                 (unsigned)ip_b2 + (n >> 16), (n >> 8) & 255, n & 255);
    else
        snprintf(buf, len, "host/h%04u.example.com", n);
}

static void *worker(void *arg)
{
    long id = (long)(intptr_t)arg;
    krb5_context ctx;
    krb5_ccache fcc, cc;
    krb5_principal client;
    char mname[32];

    /* Copy the TGT into a per-thread MEMORY ccache: the shared FILE
     * ccache takes an fcntl lock per read, which serializes all threads
     * and caps the measurement well below the KDC's capacity. */
    snprintf(mname, sizeof mname, "MEMORY:t%ld", id);
    if (krb5_init_context(&ctx) != 0 ||
        krb5_cc_resolve(ctx, ccname, &fcc) != 0 ||
        krb5_cc_get_principal(ctx, fcc, &client) != 0 ||
        krb5_cc_resolve(ctx, mname, &cc) != 0 ||
        krb5_cc_initialize(ctx, cc, client) != 0 ||
        krb5_cc_copy_creds(ctx, fcc, cc) != 0) {
        atomic_fetch_add(&n_err, per_thread);
        return NULL;
    }
    krb5_cc_close(ctx, fcc);

    unsigned seed = (unsigned)id * 2654435761u + 12345u;
    for (int i = 0; i < per_thread; i++) {
        char sname[128];
        seed = seed * 1103515245u + 12345u;
        service_name(sname, sizeof sname, (seed >> 8) % (unsigned)nhosts);

        krb5_creds in, *out = NULL;
        memset(&in, 0, sizeof in);
        in.client = client;
        if (krb5_parse_name(ctx, sname, &in.server) != 0) {
            atomic_fetch_add(&n_err, 1);
            continue;
        }
        if (krb5_get_credentials(ctx, KRB5_GC_NO_STORE, cc, &in, &out) == 0) {
            atomic_fetch_add(&n_ok, 1);
            krb5_free_creds(ctx, out);
        } else {
            atomic_fetch_add(&n_err, 1);
        }
        krb5_free_principal(ctx, in.server);
    }

    krb5_free_principal(ctx, client);
    krb5_cc_close(ctx, cc);
    krb5_free_context(ctx);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 5 && argc != 6) {
        fprintf(stderr,
                "usage: %s <ccname> <threads> <reqs-per-thread> <nhosts> "
                "[ip:A.B]\n",
                argv[0]);
        return 2;
    }
    ccname = argv[1];
    int threads = atoi(argv[2]);
    per_thread = atoi(argv[3]);
    nhosts = atoi(argv[4]);
    if (argc == 6) {
        if (sscanf(argv[5], "ip:%d.%d", &ip_b1, &ip_b2) != 2) {
            fprintf(stderr, "bad ip base: %s\n", argv[5]);
            return 2;
        }
        ip_mode = 1;
    }

    pthread_t *tids = calloc((size_t)threads, sizeof *tids);
    for (long i = 0; i < threads; i++)
        pthread_create(&tids[i], NULL, worker, (void *)(intptr_t)i);
    for (int i = 0; i < threads; i++)
        pthread_join(tids[i], NULL);
    free(tids);

    printf("ok=%ld err=%ld\n", atomic_load(&n_ok), atomic_load(&n_err));
    return atomic_load(&n_err) ? 1 : 0;
}
