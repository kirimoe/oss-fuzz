#!/bin/bash

# Define output directory
OUTPUT_DIR=~/oss-fuzz/build/output/yara

# Create an archive directory if it doesn't exist
ARCHIVE_DIR=~/oss-fuzz/build/output/yara/archive
mkdir -p $ARCHIVE_DIR

# Check if crashes directory exists, then archive old crashes
if [ -d "$OUTPUT_DIR/crashes" ]; then
  timestamp=$(date +"%Y%m%d%H%M%S")
  tar -czf $ARCHIVE_DIR/crashes_$timestamp.tar.gz -C $OUTPUT_DIR crashes
fi

# Check if inputs directory exists, then archive old inputs
if [ -d "$OUTPUT_DIR/inputs" ]; then
  timestamp=$(date +"%Y%m%d%H%M%S")
  tar -czf $ARCHIVE_DIR/inputs_$timestamp.tar.gz -C $OUTPUT_DIR inputs
fi

# Run the fuzzer (this will overwrite crashes and inputs directories)
sudo python3 infra/helper.py run_fuzzer \
  --corpus-dir=~/oss-fuzz/build/corpus/yara/yara_rules_fuzzer \
  yara yara_rules_fuzzer \
  -- -max_total_time=30 \
  -output-dir=$OUTPUT_DIR

# Optionally, you can manually move any new crashes or inputs to the archive after this run
