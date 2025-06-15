#include <cstddef>  // For size_t
#include <cstdint>  // For uint8_t
#include <cstdio>   // For fprintf (only in initialization)
#include <cstring>  // For memcpy
#include "yara.h"   // YARA library header

// Define the structure for handling custom stream data.
// This allows us to treat the fuzzer's input buffer as a file-like stream for YARA.
typedef struct {
    const uint8_t *data; // Pointer to the raw input data from the fuzzer.
    size_t size;         // Total size of the input data.
    size_t offset;       // Current read position within the data.
} CustomStreamData;

// Define the custom read function for YARA's stream API.
// YARA will call this function whenever it needs to read data from our "stream".
size_t custom_stream_read(void *ptr, size_t size, size_t count, void *user_data) {
    CustomStreamData *s = (CustomStreamData *)user_data; // Cast user_data back to our struct.
    size_t want = size * count;                         // Calculate total bytes requested.
    size_t available = s->size - s->offset;             // Bytes remaining in our buffer.

    // Ensure we don't read beyond the available data.
    if (want > available) {
        want = available;
    }

    // Copy the requested bytes from our data buffer to YARA's buffer.
    memcpy(ptr, s->data + s->offset, want);

    // Advance our read offset.
    s->offset += want;

    // Return the number of "items" read (equivalent to bytes if size is 1).
    return want / size;
}

// --- Fuzzer Entry Points ---

// LLVMFuzzerInitialize is called once at the start of the fuzzing process.
// It's the ideal place for one-time library initialization.
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // Initialize the YARA library. This must be done once per process.
    if (yr_initialize() != ERROR_SUCCESS) {
        // If YARA initialization fails, it's a critical error for the fuzzer.
        // We print to stderr to avoid interfering with fuzzer stdout/corpus.
        fprintf(stderr, "ERROR: YARA initialization failed during fuzzer setup!\n");
        // Depending on the fuzzing environment, you might want to exit here,
        // but returning 0 allows the fuzzer to proceed, though with potential issues.
        // For production fuzzing, a non-zero exit or abort() might be preferable.
    }
    return 0;
}

// LLVMFuzzerTestOneInput is the main fuzzer entry point.
// It's called repeatedly by the fuzzing engine with new, mutated input data.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // 1. Prepare the custom stream data structure from the fuzzer's input.
    CustomStreamData s = { data, size, 0 };

    // 2. Set up the YARA stream object, linking it to our data and read function.
    YR_STREAM ys = { .user_data = &s, .read = custom_stream_read };

    YR_RULES *rules = NULL; // Pointer to hold compiled YARA rules.

    // 3. Attempt to load YARA rules from our custom stream.
    // The core of the fuzzer: we feed arbitrary data and see how YARA handles it.
    // We don't print errors here; the fuzzer engine will detect crashes/hangs.
    if (yr_rules_load_stream(&ys, &rules) == ERROR_SUCCESS) {
        // If rules were successfully loaded (i.e., the input was valid YARA syntax),
        // we must destroy them to free memory and prevent leaks during long fuzzing runs.
        yr_rules_destroy(rules);
    }
    // If yr_rules_load_stream returns an error, 'rules' will be NULL,
    // and no cleanup is needed by us. The fuzzer's job is to detect if this
    // "error handling" by YARA actually leads to a crash or undefined behavior.

    // Always return 0. The fuzzer engine determines success/failure based on crashes/hangs.
    return 0;
}

// Note on yr_finalize():
// For typical fuzzer setups (especially LibFuzzer), yr_finalize() is usually
// NOT called within LLVMFuzzerTestOneInput, nor is it explicitly needed in LLVMFuzzerInitialize.
// The fuzzing process might run in a single long-lived process, or the OS cleans up
// resources upon process exit. Calling yr_finalize() repeatedly would be inefficient,
// and calling it once at the end of the fuzzer's lifetime is usually implicitly handled
// or not strictly necessary if the fuzzer is designed for continuous operation.