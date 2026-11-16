/* Planted by the egress escape tests (slice 2c.11, issue #195).
 *
 * A shared object that OpenSSL's libcrypto loads when the process's
 * OPENSSL_CONF names a configuration that points a provider or engine at it, or
 * when it is placed, named fips.so, in the directory OPENSSL_MODULES names and
 * OPENSSL_FORCE_FIPS_MODE or OPENSSL_FIPS_MODE_SWITCH_PATH turns the FIPS module
 * on. Its constructor runs when libcrypto dlopen()s it, which is while
 * libcrypto is initialised -- here, when the action's Python runs "import
 * hashlib". It appends one line to MARKERS, and only in a process whose
 * environment holds OBAAF_EGRESS_SCRIPT, as each of the egress action's own
 * steps does, so the test's other steps leave no line. It reads nothing of the
 * key and does nothing else.
 *
 * The test's point is only this: at the action's floor the line is written (a
 * module the workflow named ran in the step that holds the model key), and
 * after slice 2c.11's fix it is not, because the action removes every OPENSSL_
 * variable before libcrypto is initialised.
 */
#include <stdio.h>
#include <stdlib.h>

#ifndef MARKERS
#error "build with -DMARKERS='\"/path/to/markers\"'"
#endif

__attribute__((constructor)) static void obaaf_openssl_marker(void) {
    if (!getenv("OBAAF_EGRESS_SCRIPT"))
        return;
    FILE *f = fopen(MARKERS, "a");
    if (f) {
        fputs("OPENSSL module loaded\n", f);
        fclose(f);
    }
}

/* Present so libcrypto accepts the file as a provider module. It need not
 * succeed: the constructor above has already run by the time libcrypto calls
 * this, because dlopen() runs a library's constructors as it maps it. */
int OSSL_provider_init(const void *handle, const void *in, const void **out, void **provctx) {
    (void)handle;
    (void)in;
    (void)out;
    (void)provctx;
    return 0;
}
