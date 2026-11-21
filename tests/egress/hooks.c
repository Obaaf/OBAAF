/* Planted by the escape tests (slice 2c.9, issues #139 and #145).
 *
 * A library the dynamic loader loads into a process when LD_PRELOAD (built
 * without AUDIT) or LD_AUDIT (built with -DAUDIT) names it. It appends one
 * line to MARKERS, and only in a process whose environment holds
 * OBAAF_EGRESS_SCRIPT, as each of the egress action's own steps does, so the
 * test's other steps leave no line. It reads the environment from
 * /proc/self/environ, because an audit library runs before the C library of
 * its namespace is set up. It does nothing else.
 */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#ifndef MARKERS
#error "build with -DMARKERS='\"/path/to/markers\"'"
#endif

static char environ_copy[1 << 20];

static int wanted(void) {
    const char *key = "OBAAF_EGRESS_SCRIPT=";
    size_t key_len = strlen(key);
    int fd = open("/proc/self/environ", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    size_t total = 0;
    ssize_t got;
    while (total < sizeof environ_copy - 1 &&
           (got = read(fd, environ_copy + total, sizeof environ_copy - 1 - total)) > 0)
        total += (size_t)got;
    close(fd);
    environ_copy[total] = '\0';
    for (size_t at = 0; at < total; at += strlen(environ_copy + at) + 1)
        if (strncmp(environ_copy + at, key, key_len) == 0)
            return 1;
    return 0;
}

static void mark(const char *how) {
    if (!wanted())
        return;
    char exe[512];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n <= 0) {
        exe[0] = '?';
        n = 1;
    }
    exe[n] = '\0';
    char line[700];
    size_t len = 0;
    const char *parts[] = {how, " loaded into ", exe, "\n"};
    for (size_t i = 0; i < 4; i++) {
        size_t part = strlen(parts[i]);
        if (len + part >= sizeof line)
            part = sizeof line - 1 - len;
        memcpy(line + len, parts[i], part);
        len += part;
    }
    int fd = open(MARKERS, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
    if (fd >= 0) {
        ssize_t ignored = write(fd, line, len);
        (void)ignored;
        close(fd);
    }
}

#ifdef AUDIT
unsigned int la_version(unsigned int version) {
    mark("LD_AUDIT");
    return version;
}
#else
__attribute__((constructor)) static void preloaded(void) { mark("LD_PRELOAD"); }
#endif
