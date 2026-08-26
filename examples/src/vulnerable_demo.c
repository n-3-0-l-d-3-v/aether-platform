/* Deliberately unsafe demo target for Aether's evaluation suite.
 * Not a real program: it exists so the evaluation harness has a binary whose
 * ground truth (strings, imports, risky APIs) is known exactly. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *AWS_KEY   = "AKIAIOSFODNN7EXAMPLE";
static const char *BANNER    = "BusyBox v1.31.1 (2020-04-12 15:00:00 UTC) multi-call binary";
static const char *SSL_TAG   = "OpenSSL 1.0.2u  20 Dec 2019";
static const char *DB_URL    = "mysql://svcuser:hunter2@10.4.0.9:3306/telemetry";

void handle_name(const char *input) {
    char buffer[64];
    strcpy(buffer, input);          /* unbounded copy */
    printf("hello %s\n", buffer);
}

void run_diagnostics(const char *host) {
    char command[256];
    sprintf(command, "ping -c 1 %s", host);
    system(command);                /* command injection surface */
}

int weak_token(void) {
    srand(1234);
    return rand();
}

int main(int argc, char **argv) {
    printf("%s / %s\n", BANNER, SSL_TAG);
    if (argc > 1) {
        handle_name(argv[1]);
        run_diagnostics(argv[1]);
    }
    printf("token=%d key=%s db=%s\n", weak_token(), AWS_KEY, DB_URL);
    return 0;
}
