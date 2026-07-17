# pgvictoria Command-Line Interface (pgvictoria-cli)

`pgvictoria-cli` is the command-line utility used to generate performance and configuration reports for PostgreSQL, either online by query execution on active servers or offline directly on configuration files.

## Usage

```bash
pgvictoria-cli [ -c CONFIG_FILE ] [ -u USERS_FILE ] [ -pg VERSION ] [ -f FORMAT ] [ -t TYPE ] [ -o OUTPUT_FILE ] [ COMMAND ]
```

## Options

*   **-c, --config CONFIG_FILE**
    Set the path to the main `pgvictoria.conf` configuration file (defaults to `/etc/pgvictoria/pgvictoria.conf`).

*   **-u, --users USERS_FILE**
    Set the path to the `pgvictoria_users.conf` configuration file (defaults to `/etc/pgvictoria/pgvictoria_users.conf`).

*   **-H, --host HOST**
    Set the host name or IP address of the target PostgreSQL server (defaults to `127.0.0.1`).

*   **-P, --port PORT**
    Set the port number of the target PostgreSQL server (defaults to `5432`).

*   **-U, --user USER**
    Set the database user name (defaults to `postgres`).

*   **-W, --password PASSWORD**
    Set the database password for authentication.

*   **-pg, --postgresql VERSION**
    Override the PostgreSQL baseline version to compare against. Useful in offline file reporting modes when no version can be auto-detected. Valid values are `14` to `19`.

*   **-f, --format FORMAT**
    Select the report format: `text` (default), `html`, or `md` (`markdown` is accepted as a synonym for `md`). If omitted, the format is automatically detected from the output file extension (`.html` -> HTML, `.md`/`.markdown` -> Markdown, other -> Text). Honored in both online and offline modes.

*   **-t, --type TYPE**
    Select which settings to list: `changed` (default) shows only settings whose value differs from the version baseline, while `full` lists every setting. Honored in both online and offline modes.

*   **-o, --output OUTPUT_FILE**
    Write the report to `OUTPUT_FILE` (its parent directory is created if needed). Honored in both modes and required for every format; the `report` command errors without it.

*   **-V, --version**
    Display version information.

*   **-?, --help**
    Display the help and usage guide.

## Commands

### report

Generates a configuration comparison report against the target version's default out-of-the-box configuration baseline. The format (`-f`), type (`-t`), and destination (`-o`) flags work identically in both modes; the only difference is the data source. By default only changed settings are listed; pass `-t full` to include settings left at their baseline default.

```bash
pgvictoria-cli [ -f FORMAT ] [ -t TYPE ] [ -o OUTPUT_FILE ] report [ input_config_file ]
```

#### Online Mode (no positional argument)
Runs a connection-based configuration scan against the target PostgreSQL server (via `SHOW ALL`). The connection settings come from `-c`/`-H`/`-P`/`-U`/`-W`. The report is always written to the `-o` path; choose the format with `-f` (`text` by default, or `html`/`md`).
```bash
pgvictoria-cli -c pgvictoria-cli.conf -o report.txt report
pgvictoria-cli -c pgvictoria-cli.conf -f md -o report.md report
```

#### Offline File Mode (one positional argument)
Runs a static scan comparing `<input_config_file>` against the detected (or `-pg` overridden) version default. The flags are the same as online mode.
```bash
pgvictoria-cli -o report.txt report /etc/postgresql/18/main/postgresql.conf
pgvictoria-cli -pg 18 -f md -o report.md report /etc/postgresql/18/main/postgresql.conf
```
