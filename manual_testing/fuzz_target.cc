#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "yara.h"

// This is the custom stream read function
size_t custom_stream_read(void *ptr, size_t size, size_t count, void *user_data) {
    const uint8_t *data = (const uint8_t *)user_data;
    size_t available = size * count;

    // Ensure available size does not exceed the actual buffer size
    size_t buffer_size = *(size_t *)user_data;  // First 8 bytes contain buffer size info
    
    // If buffer size is smaller than requested read size, adjust the available size
    if (available > buffer_size) {
        available = buffer_size;
    }

    memcpy(ptr, data, available);
    return available;
}

extern "C" {
    // This is the fuzz target function
    int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        // Ensure size is greater than zero and not null
        if (size == 0 || data == nullptr) {
            return 0;
        }

        YR_RULES *rules = nullptr;
        yr_initialize();  // Initialize YARA

        // Create a custom YR_STREAM from fuzzed input data
        YR_STREAM stream;
        stream.user_data = (void *)data;  // This is our input buffer
        stream.read = custom_stream_read; // Use our custom read function
        
        // Load rules from the stream
        int result = yr_rules_load_stream(&stream, &rules);

        // If the rules are successfully loaded, we can process them
        if (result == ERROR_SUCCESS && rules) {
            // The rules are valid and compiled, process them
            // For now, we're just verifying successful load
        }

        if (rules) {
            yr_rules_destroy(rules);  // Clean up the rules
        }

        yr_finalize();  // Finalize YARA
        return 0; // Return success
    }
}