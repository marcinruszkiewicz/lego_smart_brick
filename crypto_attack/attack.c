/*
 * Optimized Grain-128A key search for Apple Silicon (M4).
 *
 * Three layers of parallelism:
 *   1. Bitslicing: 64 key candidates per clock cycle (uint64_t words)
 *   2. Multi-threading: pthreads across all CPU cores
 *   3. Early exit: bail on first constraint byte mismatch (survivors==0)
 *
 * The inner loop tests 64 keys against all sparse constraints in one pass.
 * A "batch" = 64 keys; each thread processes many batches.
 */

#include "grain128a.h"
#include "grain128a_bs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/sysctl.h>
#include <stdatomic.h>

static sparse_constraint_t CONSTRAINTS[MAX_CONSTRAINTS];
static int NUM_CONSTRAINTS = 0;

static int get_ncpus(void) {
    int n = 0;
    size_t sz = sizeof(n);
    if (sysctlbyname("hw.ncpu", &n, &sz, NULL, 0) != 0) n = 4;
    return n > 0 ? n : 4;
}

/* ---------- Benchmark (scalar vs bitsliced) ---------- */

static void benchmark(int nthreads) {
    uint8_t key[16] = {0}, iv[12] = {0};
    uint8_t ks[64];

    printf("=== Scalar baseline ===\n");
    clock_t t0 = clock();
    long count = 0;
    while ((clock() - t0) < 2 * CLOCKS_PER_SEC) {
        grain_state_t s;
        grain_init(&s, key, iv);
        grain_keystream(&s, ks, 64);
        key[0] ^= ks[0];
        count++;
    }
    double elapsed = (double)(clock() - t0) / CLOCKS_PER_SEC;
    double scalar_rate = count / elapsed;
    printf("  %.0f keys/sec (single-core, scalar)\n", scalar_rate);

    printf("\n=== Bitsliced (64-wide, single-core) ===\n");
    uint8_t keys[BS_WIDTH][16];
    memset(keys, 0, sizeof(keys));
    for (int k = 0; k < BS_WIDTH; k++)
        keys[k][0] = (uint8_t)k;

    sparse_constraint_t dummy;
    memset(&dummy, 0, sizeof(dummy));
    dummy.num_known = 1;
    dummy.offsets[0] = 0;
    dummy.expected[0] = 0xFF;
    dummy.max_offset = 0;

    t0 = clock();
    long bs_batches = 0;
    while ((clock() - t0) < 2 * CLOCKS_PER_SEC) {
        bs_test_keys((const uint8_t (*)[16])keys, BS_WIDTH, &dummy);
        keys[0][1]++;
        bs_batches++;
    }
    elapsed = (double)(clock() - t0) / CLOCKS_PER_SEC;
    double bs_rate = (bs_batches * BS_WIDTH) / elapsed;
    printf("  %.0f keys/sec (single-core, bitsliced)\n", bs_rate);
    printf("  Speedup vs scalar: %.1fx\n", bs_rate / scalar_rate);

    double total_rate = bs_rate * nthreads;
    printf("\n=== Projected multi-core (%d threads) ===\n", nthreads);
    printf("  ~%.0f keys/sec\n", total_rate);

    double two64 = (double)(1ULL << 32) * (double)(1ULL << 32);
    double secs = two64 / total_rate;
    printf("  2^64 keyspace: %.1e sec = %.1f years\n", secs, secs / 86400.0 / 365.25);

    double two48 = (double)(1ULL << 48);
    double secs48 = two48 / total_rate;
    printf("  2^48 keyspace: %.1e sec = %.1f days\n", secs48, secs48 / 86400.0);
}

/* ---------- Multi-threaded search ---------- */

typedef struct {
    uint64_t start;
    uint64_t end;
    const sparse_constraint_t *constraints;
    int num_constraints;
    atomic_int *found;
    uint8_t found_key[16];
    uint64_t tested;
} thread_arg_t;

static void *search_thread(void *arg) {
    thread_arg_t *a = (thread_arg_t *)arg;
    uint8_t keys[BS_WIDTH][16];
    a->tested = 0;

    for (uint64_t base = a->start; base < a->end; base += BS_WIDTH) {
        if (atomic_load(a->found)) return NULL;

        int batch = BS_WIDTH;
        if (base + BS_WIDTH > a->end)
            batch = (int)(a->end - base);

        memset(keys, 0, sizeof(keys));
        for (int k = 0; k < batch; k++) {
            uint64_t val = base + k;
            for (int j = 0; j < 8; j++)
                keys[k][j] = (uint8_t)(val >> (8 * j));
        }

        uint64_t pass = (batch == BS_WIDTH) ? ~0ULL : ((1ULL << batch) - 1);

        for (int c = 0; c < a->num_constraints && pass; c++) {
            pass &= bs_test_keys((const uint8_t (*)[16])keys, batch,
                                 &a->constraints[c]);
        }

        if (pass) {
            int idx = __builtin_ctzll(pass);
            memcpy(a->found_key, keys[idx], 16);
            atomic_store(a->found, 1);
            return NULL;
        }

        a->tested += batch;
    }
    return NULL;
}

static void search(uint64_t start, uint64_t count, int nthreads) {
    if (NUM_CONSTRAINTS == 0) {
        fprintf(stderr, "No constraints loaded. Use --constraints <file>.\n");
        exit(1);
    }

    printf("Search: start=0x%016llx count=%llu threads=%d (bitsliced %d-wide)\n",
           (unsigned long long)start, (unsigned long long)count, nthreads, BS_WIDTH);

    atomic_int found = 0;
    thread_arg_t *args = calloc(nthreads, sizeof(thread_arg_t));
    pthread_t *threads = calloc(nthreads, sizeof(pthread_t));

    uint64_t per_thread = ((count + nthreads - 1) / nthreads + BS_WIDTH - 1)
                          / BS_WIDTH * BS_WIDTH;

    for (int t = 0; t < nthreads; t++) {
        args[t].start = start + t * per_thread;
        args[t].end = args[t].start + per_thread;
        if (args[t].end > start + count) args[t].end = start + count;
        args[t].constraints = CONSTRAINTS;
        args[t].num_constraints = NUM_CONSTRAINTS;
        args[t].found = &found;
        args[t].tested = 0;
    }

    struct timespec ts0, ts1;
    clock_gettime(CLOCK_MONOTONIC, &ts0);

    for (int t = 0; t < nthreads; t++)
        pthread_create(&threads[t], NULL, search_thread, &args[t]);

    /* Progress monitor in main thread */
    for (;;) {
        struct timespec req = {0, 500000000L}; /* 500ms */
        nanosleep(&req, NULL);

        if (atomic_load(&found)) break;

        uint64_t total = 0;
        for (int t = 0; t < nthreads; t++) total += args[t].tested;

        clock_gettime(CLOCK_MONOTONIC, &ts1);
        double wall = (ts1.tv_sec - ts0.tv_sec) + (ts1.tv_nsec - ts0.tv_nsec) / 1e9;
        double rate = total / wall;
        printf("\r  Tested %llu keys (%.0f/sec, %.1f%%)    ",
               (unsigned long long)total, rate, 100.0 * total / count);
        fflush(stdout);

        if (total >= count) break;
    }

    for (int t = 0; t < nthreads; t++)
        pthread_join(threads[t], NULL);

    clock_gettime(CLOCK_MONOTONIC, &ts1);
    double wall = (ts1.tv_sec - ts0.tv_sec) + (ts1.tv_nsec - ts0.tv_nsec) / 1e9;

    uint64_t total = 0;
    for (int t = 0; t < nthreads; t++) total += args[t].tested;

    if (atomic_load(&found)) {
        int winner = -1;
        for (int t = 0; t < nthreads; t++) {
            if (args[t].found_key[0] || args[t].found_key[1]) { winner = t; break; }
        }
        if (winner >= 0) {
            printf("\n\n*** KEY FOUND: ");
            for (int j = 0; j < 16; j++) printf("%02X", args[winner].found_key[j]);
            printf(" ***\n");
        }
    } else {
        printf("\n  Done: %llu keys in %.1f sec (%.0f keys/sec) — no match.\n",
               (unsigned long long)total, wall, total / wall);
    }

    free(args);
    free(threads);
}

/* ---------- Key file testing ---------- */

static void try_key_file(const char *path) {
    if (NUM_CONSTRAINTS == 0) {
        fprintf(stderr, "No constraints loaded. Use --constraints <file>.\n");
        exit(1);
    }

    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "Cannot open key file: %s\n", path); exit(1); }

    char line[256];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strlen(line) < 32) continue;
        uint8_t key[16];
        for (int i = 0; i < 16; i++)
            sscanf(&line[i * 2], "%2hhx", &key[i]);

        /* Scalar test for individual keys */
        bool match = true;
        for (int c = 0; c < NUM_CONSTRAINTS && match; c++) {
            grain_state_t gs;
            grain_init(&gs, key, CONSTRAINTS[c].iv);
            uint8_t ks[256];
            int need = CONSTRAINTS[c].max_offset + 1;
            grain_keystream(&gs, ks, need);
            for (int i = 0; i < CONSTRAINTS[c].num_known; i++) {
                if (ks[CONSTRAINTS[c].offsets[i]] != CONSTRAINTS[c].expected[i]) {
                    match = false; break;
                }
            }
        }
        if (match) {
            printf("*** KEY FOUND: %.*s\n", 32, line);
            fclose(f);
            return;
        }
        count++;
    }
    fclose(f);
    printf("Tested %d keys from %s — no match.\n", count, path);
}

/* ---------- Main ---------- */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --verify              Run cipher self-test (scalar + bitsliced)\n"
        "  --benchmark           Benchmark scalar vs bitsliced throughput\n"
        "  --constraints <file>  Load sparse keystream constraints\n"
        "  --search              Multi-threaded search\n"
        "  --count <N>           Keys to search (default 100M, supports 1e9 notation)\n"
        "  --start <N>           Start offset for search (default 0)\n"
        "  --threads <N>         Number of threads (default: all CPUs)\n"
        "  --keys <file>         Test hex keys from file\n"
        "  --help                Show this message\n",
        prog);
}

int main(int argc, char *argv[]) {
    static struct option long_opts[] = {
        {"verify",      no_argument,       NULL, 'v'},
        {"benchmark",   no_argument,       NULL, 'b'},
        {"constraints", required_argument, NULL, 'c'},
        {"search",      no_argument,       NULL, 's'},
        {"count",       required_argument, NULL, 'n'},
        {"start",       required_argument, NULL, 'S'},
        {"threads",     required_argument, NULL, 't'},
        {"keys",        required_argument, NULL, 'k'},
        {"help",        no_argument,       NULL, 'h'},
        {0, 0, 0, 0}
    };

    int do_verify = 0, do_bench = 0, do_search = 0;
    uint64_t search_count = 100000000ULL;
    uint64_t search_start = 0;
    int nthreads = get_ncpus();
    const char *constraint_file = NULL;
    const char *key_file = NULL;

    int opt;
    while ((opt = getopt_long(argc, argv, "vbc:sn:S:t:k:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'v': do_verify = 1; break;
            case 'b': do_bench = 1; break;
            case 'c': constraint_file = optarg; break;
            case 's': do_search = 1; break;
            case 'n': search_count = (uint64_t)strtod(optarg, NULL); break;
            case 'S': search_start = (uint64_t)strtod(optarg, NULL); break;
            case 't': nthreads = atoi(optarg); break;
            case 'k': key_file = optarg; break;
            case 'h': default: usage(argv[0]); return opt == 'h' ? 0 : 1;
        }
    }

    /* Treat remaining positional args as count (for convenience: --search 2e11) */
    if (optind < argc && do_search) {
        search_count = (uint64_t)strtod(argv[optind], NULL);
    }

    if (argc == 1) { usage(argv[0]); return 0; }

    printf("Grain-128A key search — %d CPU cores detected\n\n", get_ncpus());

    if (do_verify) {
        grain_self_test();
        bs_self_test();
        printf("\n");
    }

    if (constraint_file) {
        NUM_CONSTRAINTS = load_sparse_constraints(constraint_file, CONSTRAINTS,
                                                  MAX_CONSTRAINTS);
        printf("Loaded %d sparse constraints (%d known bytes each)\n\n",
               NUM_CONSTRAINTS,
               NUM_CONSTRAINTS > 0 ? CONSTRAINTS[0].num_known : 0);
    }

    if (do_bench) benchmark(nthreads);

    if (key_file) try_key_file(key_file);

    if (do_search) search(search_start, search_count, nthreads);

    return 0;
}
