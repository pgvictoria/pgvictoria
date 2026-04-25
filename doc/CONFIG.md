# pgvictoria-config

`pgvictoria-config` is a command-line utility designed to simplify the generation and management of the `pgvictoria.conf` configuration file. It provides an interactive way to initialize a configuration and a non-interactive way to modify settings.

## Initialization

To create a new `pgvictoria.conf` file, use the `init` command:

Command:
```
pgvictoria-config init
```

This will guide you through the process of defining the listener address, logging, and your PostgreSQL servers.

By default, this will create a file named `pgvictoria.conf` in the current directory. You can specify a different output path using the `-o` or `--output` flag:

Example:
```
pgvictoria-config -o /etc/pgvictoria/pgvictoria.conf init
```

### Quiet Mode

If you want to generate a configuration file with default values without any user interaction, use the `-q` or `--quiet` flag:

Example:
```
pgvictoria-config -q init
```

### Force Overwrite

If the output file already exists, `pgvictoria-config` will ask for confirmation before overwriting it. To force an overwrite, use the `-F` or `--force` flag:

Example:
```
pgvictoria-config -F init
```

## Management

`pgvictoria-config` also provides commands to inspect and modify existing configuration files.

### Listing Sections and Keys

To list all sections in a configuration file:

Command:
```
pgvictoria-config ls pgvictoria.conf
```

To list all keys in a specific section:

Command:
```
pgvictoria-config ls pgvictoria.conf pgvictoria
```

### Getting Values

To retrieve the value of a specific configuration key:

Command:
```
pgvictoria-config get pgvictoria.conf pgvictoria log_level
```

### Setting Values

To set or update the value of a configuration key:

Command:
```
pgvictoria-config set pgvictoria.conf pgvictoria log_level debug
```

This command ensures that:
1.  The file is updated atomically (using a temporary file and `rename`).
2.  Comments and formatting of other lines are preserved.
3.  Permissions are set to `0600`.

### Deleting Keys and Sections

To delete a specific configuration key:

Command:
```
pgvictoria-config del pgvictoria.conf pgvictoria log_path
```

To delete an entire section:

Command:
```
pgvictoria-config del pgvictoria.conf primary
```

## Security

`pgvictoria-config` follows best practices for security:
- It refuses to run as `root` to prevent accidental modification of system-wide files with incorrect ownership.
- It creates and maintains files with strict permissions (`0600`), ensuring that only the owner can read or write the configuration.
