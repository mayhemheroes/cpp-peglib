#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../peglib.h"
using namespace peg;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    char* in_data = (char*) malloc(Size);
    memcpy(in_data, Data, Size);
    parser parser(in_data, Size);
    free(in_data);
    return 0;
}