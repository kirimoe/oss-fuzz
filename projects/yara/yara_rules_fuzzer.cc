#include <yara.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>

size_t custom_stream_read(void *ptr, size_t size, size_t count, void *user_data) {
    const uint8_t *data = (const uint8_t *)user_data;
    size_t available = size * count;
    
    // Make sure we don't overrun the buffer
    if (available > size) {
        available = size;
    }

    memcpy(ptr, data, available);
    return available;
}

void LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    YR_RULES *rules = NULL;
    yr_initialize();  // Initialize YARA

    // Create a custom YR_STREAM from fuzzed input data
    YR_STREAM stream;
    stream.user_data = (void*)data;  // This is our input buffer
    stream.read = custom_stream_read; // Use our custom read function
    
    // Load rules from the stream
    int result = yr_rules_load_stream(&stream, &rules);

    if (result == ERROR_SUCCESS) {
        // You can process the loaded rules here
    }

    if (rules) {
        yr_rules_destroy(rules);
    }

    yr_finalize();
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 4) return 0;  // too small to be a valid .yarac

  yr_initialize();

  FuzzContext ctx = { data, size, 0 };
  YR_RULES* rules = nullptr;

  YR_STREAM stream = {
    .user_data = &ctx,
    .read = fuzz_read_callback  // This should now match the expected signature
  };

  // Attempt to load rules from the fuzzed input
  yr_rules_load_stream(&stream, &rules);

  if (rules != nullptr) {
    yr_rules_destroy(rules);
  }

  yr_finalize();
  return 0;
}
