#include <vector>        // stdlib — must be filtered by IncludeScanner
#include <string>        // stdlib — must be filtered
#include <openssl/ssl.h> // third-party — must appear as "openssl"
#include <fmt/core.h>    // third-party — must appear as "fmt"

int main() {
    fmt::print("Hello, SBOM!\n");
    return 0;
}
