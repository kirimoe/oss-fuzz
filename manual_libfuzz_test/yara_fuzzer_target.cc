#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstdint> // For uint8_t, size_t in C++
#include "yara.h"

// Define a static variable to ensure YARA is initialized only once.
// In C++, it's common to use a static boolean or a more robust
// Meyers singleton pattern for one-time initialization, but for a fuzzer
// simple static variable is usually sufficient and avoids extra dependencies.
static bool yara_initialized = false;

// Custom stream data structure for YARA's stream reader
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} CustomStreamData;

// Custom stream read function for YARA
size_t custom_stream_read(void *ptr, size_t size, size_t count, void *user_data) {
    CustomStreamData *s = static_cast<CustomStreamData *>(user_data);
    size_t want = size * count;
    size_t available = s->size - s->offset;

    if (want > available) {
        want = available;
    }

    // Ensure we don't copy from a null data pointer if size is 0
    if (s->data != nullptr && want > 0) {
        memcpy(ptr, s->data + s->offset, want);
    }
    s->offset += want;
    return want / size; // YARA expects number of items read, not bytes
}

// --- LibFuzzer Entry Point ---
// This function is called repeatedly by LibFuzzer with different inputs.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Initialize YARA only once per process.
    // This is crucial for performance and correctness in fuzzing.
    if (!yara_initialized) {
        // If YARA initialization fails, there's a fundamental issue.
        // In a fuzzer, we just return to avoid crashing the fuzzer itself.
        if (yr_initialize() != ERROR_SUCCESS) {
            return 0;
        }
        yara_initialized = true;
    }

    // Prepare the custom stream data from the fuzzer's input
    CustomStreamData s = { Data, Size, 0 };
    YR_STREAM ys = { .user_data = &s, .read = custom_stream_read };
    YR_RULES *rules = nullptr; // Initialize to nullptr for safety

    // Attempt to load rules from the fuzzer's input data
    // We don't check the return value here directly, as the goal of the fuzzer
    // is to find crashes, not to report parsing errors. YARA will return
    // an error code for invalid rules, but a crash would be a bug.
    yr_rules_load_stream(&ys, &rules);

    // If rules were successfully loaded, destroy them to prevent memory leaks.
    // This is critical for long-running fuzzers.
    if (rules != nullptr) {
        yr_rules_destroy(rules);
    }

    // Do NOT call yr_finalize() here. It should be called only once
    // when the fuzzer process exits, which LibFuzzer handles or you can
    // manage with an atexit handler in a more complex setup.
    // For typical OSS-Fuzz integration, this is not needed in TestOneInput.

    return 0; // Always return 0 for success (continue fuzzing) in LibFuzzer
}

// Optional: LLVMFuzzerInitialize can be used for one-time setup
// This function is called once by LibFuzzer at startup, before any test inputs.
// It's a good place for truly global setup that doesn't need to be conditional.
// The __attribute__((weak)) allows for user-defined overrides if needed.
extern "C" __attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // Our YARA initialization is handled within LLVMFuzzerTestOneInput for robustness,
    // ensuring it's always initialized even if this specific function isn't called
    // or if the fuzzer runtime changes. If you had other global setup, it would go here.
    (void)argc; // Mark as unused to avoid compiler warnings
    (void)argv; // Mark as unused to avoid compiler warnings
    return 0;
}
