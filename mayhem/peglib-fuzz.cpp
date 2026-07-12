#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "peglib.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *in_data = (char *)malloc(Size);
    if (!in_data && Size) return 0;
    memcpy(in_data, Data, Size);
    peg::parser parser(in_data, Size);
    free(in_data);
    return 0;
}
