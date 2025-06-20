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

FROM gcr.io/oss-fuzz-base/base-builder

# Install dependencies for building YARA (and fuzzing)
RUN apt-get update && apt-get install -y \
  automake \
  autoconf \
  make \
  libtool \
  pkg-config \
  bison \
  flex \
  libpcre3-dev \
  libssl-dev

# Clone YARA source
RUN git clone --depth 1 https://github.com/VirusTotal/yara.git

# Copy the build script and fuzzer source
COPY build.sh $SRC/
COPY yara_rules_fuzzer.cc $SRC/

# Set the working directory to /src
WORKDIR $SRC

# Run the build script
# RUN bash build.sh
