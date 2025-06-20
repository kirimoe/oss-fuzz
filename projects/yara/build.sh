#!/bin/bash -eu
# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
#!/bin/bash
set -e

cd $SRC/yara

echo "Listing files in current directory:"
ls -al

# Prepare the build
./bootstrap.sh

# Configure with options you want to enable
./configure --enable-macho --enable-debug --enable-dex --enable-dotnet --without-crypto

# Clean and build
make clean
make -j$(nproc) all
make install

# Build your specific fuzz target
FUZZER_SRC=$SRC/yara_rules_fuzzer.cc
FUZZER_BIN=$OUT/yara_rules_fuzzer

# Build the fuzzer binary
$CXX $CXXFLAGS -std=c++11 -I$SRC/yara/libyara/include \
    $FUZZER_SRC -o $FUZZER_BIN \
    /usr/local/lib/libyara.a $LIB_FUZZING_ENGINE