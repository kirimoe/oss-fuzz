#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "yara.h"

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} CustomStreamData;

size_t custom_stream_read(void *ptr, size_t size, size_t count, void *user_data) {
    CustomStreamData *s = (CustomStreamData *)user_data;
    size_t want = size * count;
    size_t available = s->size - s->offset;
    if (want > available) {
        want = available;
    }
    memcpy(ptr, s->data + s->offset, want);
    s->offset += want;
    return want / size;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "ERROR: YARA initialization failed during fuzzer setup!\n");
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    CustomStreamData s = { data, size, 0 };
    YR_STREAM ys = { .user_data = &s, .read = custom_stream_read };
    YR_RULES *rules = NULL;
    int result = yr_rules_load_stream(&ys, &rules);
    if (result == ERROR_SUCCESS ||
        result == ERROR_INSUFICIENT_MEMORY ||
        result == ERROR_INVALID_FILE ||
        result == ERROR_CORRUPT_FILE ||
        result == ERROR_UNSUPPORTED_FILE_VERSION)
    {
        if (result == ERROR_SUCCESS) {
            yr_rules_destroy(rules);
        }
    } else {
        assert(false && "yr_rules_load_stream returned an undocumented or unexpected error code!");
    }
    return 0;
}