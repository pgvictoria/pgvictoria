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

import sys
import json
import argparse
import re
import os
import subprocess
import time

SUPPORTED_VERSIONS = [14, 15, 16, 17, 18]

def parse_config(content):
    """Parses postgresql.conf format content."""
    config = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Split by equals or whitespace
        # Handles: parameter = value, parameter=value, parameter value
        match = re.match(r'^([\w\.]+)\s*[=\s]\s*(.*)$', line)
        if match:
            key, val = match.groups()
            # Remove trailing comments if exists: parameter = value # comment
            if '#' in val:
                val = val.split('#')[0].strip()

            # Strip quotes
            val = val.strip().strip("'").strip('"')
            config[key] = val
    return config


def parse_show_all(content):
    """Parses SHOW ALL tabular output."""
    config = {}
    lines = content.splitlines()
    if not lines:
        return config

    # Try to find headers
    data_start = 0
    for i, line in enumerate(lines):
        if 'name' in line.lower() and 'setting' in line.lower():
            data_start = i + 1
            # Skip divider lines like ----+---- or +-----+-----+
            if data_start < len(lines) and re.match(r'^[-+| ]+$', lines[data_start]):
                data_start += 1
            break

    # Parse data lines
    for line in lines[data_start:]:
        line = line.strip()
        if not line or line.startswith('(') or 'row' in line.lower():  # Skip footer
            continue

        # Split strictly by pipe character which separates columns in psql output
        parts = line.split('|')
        if len(parts) >= 2:
            key = parts[0].strip()
            val = parts[1].strip()
            config[key] = val

    return config


def generate_header(config, version, filename):
    """Generates a C header file with embedded JSON configuration."""
    guard = filename.replace('.', '_').replace('-', '_').upper()
    json_str = json.dumps(config, indent=2)
    # Escape for C string literal
    c_json = json_str.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n"\n  "')

    header = f"""/*
 * Copyright (C) 2026 The pgvictoria community
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 * be used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef {guard}_H
#define {guard}_H

static const char* pg{version}_json = 
  "{c_json}";

#endif
"""
    return header


def get_container_engine():
    """Detects available container engine (podman or docker)."""
    for engine in ['podman', 'docker']:
        try:
            # Run with shell=False for cleaner detection
            subprocess.run([engine, '--version'], capture_output=True, check=True)
            return engine
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    return None


def get_config_from_docker(version):
    """Extracts PostgreSQL configuration from a Docker container."""
    engine = get_container_engine()
    if not engine:
        print("Error: No container engine (podman or docker) found.", file=sys.stderr)
        sys.exit(1)

    container_name = f"pg{version}_temp_extract"
    print(f"Extracting configuration for PostgreSQL {version} via {engine}...")
    
    try:
        # 1. Start container
        subprocess.run(f"{engine} run --name {container_name} -e POSTGRES_PASSWORD=secret -d postgres:{version}", 
                       shell=True, check=True, capture_output=True)
        
        # 2. Give Postgres a few seconds to start up
        time.sleep(5)
        
        # 3. Exec SHOW ALL
        result = subprocess.run(f"{engine} exec {container_name} psql -U postgres -c \"SHOW ALL\"", 
                                shell=True, check=True, capture_output=True, text=True)
        return result.stdout
    finally:
        # Cleanup
        subprocess.run(f"{engine} rm -f {container_name}", shell=True, check=False, capture_output=True)


def process_content(content, version, output_path, input_type='auto'):
    """Processes content and saves the generated header."""
    if not content.strip():
        print(f"Error: Content for version {version} is empty.")
        return False

    # Detection logic
    if input_type == 'auto':
        conf_score = 0
        show_score = 0
        lowered_content = content.lower()
        if 'name' in lowered_content and 'setting' in lowered_content:
            show_score += 10
        if '=' in content:
            conf_score += 5
        if content.strip().startswith('#'):
            conf_score += 5
        input_type = 'conf' if conf_score >= show_score else 'show'

    if input_type == 'conf':
        config = parse_config(content)
    else:
        config = parse_show_all(content)

    if not config:
        print(f"Error: Could not parse configuration for version {version}.")
        return False

    header_content = generate_header(config, version, os.path.basename(output_path))

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(header_content)
        print(f"Successfully generated {output_path} with {len(config)} parameters.")
        return True
    except Exception as e:
        print(f"Error writing to {output_path}: {e}")
        return False


def main():
    """Main entry point for the config reporting engine."""
    parser = argparse.ArgumentParser(description='Convert PostgreSQL configuration to C header JSON string.')
    parser.add_argument('--input', help='Input file path (postgresql.conf or output of SHOW ALL).')
    parser.add_argument('--psql', action='store_true', help='Get configuration from a live PostgreSQL instance using psql.')
    parser.add_argument('--output', help='Output C header file path (e.g., pg15.h).')
    parser.add_argument('--version', help='PostgreSQL version (e.g., 15) or "all" to generate for all supported versions.')
    parser.add_argument('--type', choices=['auto', 'conf', 'show'], default='auto',
                        help='Format of the input (default: auto-detect).')

    args = parser.parse_args()

    # Manual mode check for stdin
    stdin_content = ""
    if not args.input and not args.psql and not sys.stdin.isatty():
        stdin_content = sys.stdin.read()

    # Determine execution mode
    batch_mode = args.version == "all" or (not args.version and not args.input and not args.psql and not stdin_content)
    docker_mode = (args.version or batch_mode) and not args.input and not args.psql and not stdin_content

    if batch_mode:
        print(f"Running in batch mode for versions: {SUPPORTED_VERSIONS}")
        base_dir = os.path.dirname(os.path.abspath(__file__))
        include_dir = os.path.abspath(os.path.join(base_dir, "..", "..", "src", "include"))
        
        if not os.path.exists(include_dir):
            os.makedirs(include_dir)

        success_count = 0
        for v in SUPPORTED_VERSIONS:
            content = get_config_from_docker(v)
            output_path = os.path.join(include_dir, f"pg{v}.h")
            if process_content(content, v, output_path):
                success_count += 1
        
        print(f"\nBatch processing complete. Successfully generated {success_count}/{len(SUPPORTED_VERSIONS)} headers.")
        sys.exit(0 if success_count == len(SUPPORTED_VERSIONS) else 1)

    if docker_mode:
        # Single version Docker mode
        content = get_config_from_docker(args.version)
        output_path = args.output if args.output else f"pg{args.version}.h"
        if process_content(content, args.version, output_path):
            sys.exit(0)
        sys.exit(1)

    # Manual mode (file, stdin, or live psql)
    if not args.version:
        print("Error: --version is required when providing manual input (--input, --psql, or stdin).", file=sys.stderr)
        sys.exit(1)

    content = stdin_content
    input_type = args.type

    try:
        if args.psql:
            print("Fetching configuration from psql...", file=sys.stderr)
            result = subprocess.run(['psql', '-c', 'SHOW ALL'], capture_output=True, text=True, check=True)
            content = result.stdout
            input_type = 'show'
        elif args.input:
            with open(args.input, 'r', encoding='utf-8') as f:
                content = f.read()
        elif not stdin_content:
            # Fallback to local psql
            try:
                print("No input specified, attempting to fetch from local psql...", file=sys.stderr)
                result = subprocess.run(['psql', '-c', 'SHOW ALL'], capture_output=True, text=True, check=True)
                content = result.stdout
                input_type = 'show'
            except (subprocess.CalledProcessError, FileNotFoundError):
                print("Error: No input provided and could not run psql. Use --input, --psql, or --version all.", file=sys.stderr)
                sys.exit(1)
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        sys.exit(1)

    output_path = args.output if args.output else f"pg{args.version}.h"
    if process_content(content, args.version, output_path, input_type):
        sys.exit(0)
    sys.exit(1)


if __name__ == "__main__":
    main()
