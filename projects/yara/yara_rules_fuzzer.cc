#include <yara.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    const char* tmp_path = "/tmp/fuzzed_rule.yarc";
    FILE* fp = fopen(tmp_path, "wb");
    if (!fp) return 0;

    fwrite(data, 1, size, fp);
    fclose(fp);

    if (yr_initialize() != ERROR_SUCCESS)
        return 0;

    YR_RULES* rules = NULL;
    yr_rules_load(tmp_path, &rules);

    if (rules != NULL)
        yr_rules_destroy(rules);

    yr_finalize();
    remove(tmp_path);
    return 0;
}
