#!/bin/bash
#
# Copyright (C) 2026 The pgvictoria community
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list
# of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this
# list of conditions and the following disclaimer in the documentation and/or other
# materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may
# be used to endorse or promote products derived from this software without specific
# prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

set -eo pipefail

SCRIPT_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
PROJECT_DIRECTORY="$(realpath "$SCRIPT_DIR/..")"
TEST_DIRECTORY="$PROJECT_DIRECTORY/build/test"

PGVICTORIA_ROOT_DIR="/tmp/pgvictoria-test"
BASE_DIR="$PGVICTORIA_ROOT_DIR/base"
LOG_DIR="$PGVICTORIA_ROOT_DIR/log"

cleanup() {
   echo "Clean up"
   set +e
   unset PGVICTORIA_TEST_BASE_DIR
   set -e
}

do_setup() {
   echo "Preparing pgvictoria test directories"
   rm -Rf "$PGVICTORIA_ROOT_DIR"
   mkdir -p "$PGVICTORIA_ROOT_DIR"
   mkdir -p "$LOG_DIR" "$BASE_DIR"
   
   # Create a dummy empty pgvictoria.log to prevent log slicer open error
   touch "$LOG_DIR/pgvictoria.log"

   if [ -z "$PGVICTORIA_TEST_NO_BUILD" ]; then
      echo "Building pgvictoria"
      mkdir -p "$PROJECT_DIRECTORY/build"
      (
         cd "$PROJECT_DIRECTORY/build"
         cmake -DCMAKE_BUILD_TYPE=Debug -Dcheck=TRUE ..
         make -j$(nproc)
      )
   fi
}

execute_testcases() {
   echo "Execute MCTF Testcases"
   export PGVICTORIA_TEST_BASE_DIR=$BASE_DIR
   
   set +e
   "$TEST_DIRECTORY/pgvictoria-test" "$@"
   local exit_code=$?
   set -e
   
   if [ $exit_code -ne 0 ]; then
      echo "Tests failed! See report: $LOG_DIR/pgvictoria-test-report.html"
      exit $exit_code
   fi
}

trap cleanup EXIT

do_setup
execute_testcases "$@"
