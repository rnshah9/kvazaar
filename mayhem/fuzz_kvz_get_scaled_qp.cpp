#include <stdint.h>
#include <stdio.h>
#include <climits>

#include "FuzzedDataProvider.h"

extern "C" int32_t kvz_get_scaled_qp(int8_t type, int8_t qp, int8_t qp_offset);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int8_t type = provider.ConsumeIntegral<int8_t>();
    int8_t qp = provider.ConsumeIntegral<int8_t>();
    int8_t qp_offset = provider.ConsumeIntegral<int8_t>();
    kvz_get_scaled_qp(type, qp, qp_offset);

    return 0;
}