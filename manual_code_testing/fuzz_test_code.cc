#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    if (want > available) want = available;
    memcpy(ptr, s->data + s->offset, want);
    s->offset += want;
    return want / size;
}

int main(void) {
    fseek(stdin, 0, SEEK_END);
    long size = ftell(stdin);
    rewind(stdin);

    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) return fprintf(stderr, "malloc failed\n"), 1;

    fread(buf, 1, size, stdin);

    yr_initialize();

    CustomStreamData s = { buf, (size_t)size, 0 };
    YR_STREAM ys = { .user_data = &s, .read = custom_stream_read };
    YR_RULES *rules = NULL;

    if (yr_rules_load_stream(&ys, &rules) != ERROR_SUCCESS)
        return fprintf(stderr, "yr_rules_load_stream failed\n"), free(buf), yr_finalize(), 1;

    puts("Rules loaded successfully");

    yr_rules_destroy(rules);
    free(buf);
    yr_finalize();
    return 0;
}
