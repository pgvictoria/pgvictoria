# Configuration Generator

`pgvictoria-config` is a utility tool that helps users generate and manage their `pgvictoria` configuration files. It is particularly useful for new users to set up a base configuration or for automation scripts to modify existing settings safely.

## Overview

The tool provides several commands to interact with the configuration:

*   **init**: Interactive or automatic configuration generation.
*   **get**: Retrieve a value from the configuration.
*   **set**: Modify or add a value to the configuration.
*   **del**: Remove a key or a section.
*   **ls**: List sections or keys in a section.

## Usage

### Initializing a Configuration

The most common use case is generating a fresh configuration:

Command:
```
pgvictoria-config init
```

This will guide you through the process of defining the listener address, logging, and your first PostgreSQL server.

For automated setups, you can use the quiet mode:

Example:
```
pgvictoria-config -q -o pgvictoria.conf init
```

### Modifying the Configuration

Instead of manually editing the `ini` file and potentially making syntax errors, you can use the `set` command:

Example:
```
pgvictoria-config set pgvictoria.conf pgvictoria log_level debug
```

This command ensures that:
1.  The file is updated atomically.
2.  Comments and formatting other than the modified line are preserved.
3.  Permissions are set to `0600`.

### Troubleshooting

If you need to verify what keys are available in a section:

Example:
```
pgvictoria-config ls pgvictoria.conf pgvictoria
```

Or to check a specific value:

Example:
```
pgvictoria-config get pgvictoria.conf pgvictoria host
```

## Security

`pgvictoria-config` follows the same security principles as `pgvictoria`:
*   It refuses to run as `root` to prevent misconfiguration of system files.
*   It maintains strict file permissions (`0600`) on all files it touches.
*   It uses `fsync()` to ensure data integrity during writes.
