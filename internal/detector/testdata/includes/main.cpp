#include <vector>           // stdlib — should be filtered
#include <string>            // stdlib — should be filtered
#include <iostream>          // stdlib — should be filtered
#include <openssl/ssl.h>     // third-party — should appear as "openssl"
#include <boost/regex.hpp>   // third-party — should appear as "boost"
#include "internal/myheader.h"  // internal path — should be filtered
#include "../sibling.h"      // relative path — should be filtered

int main() {
    return 0;
}
