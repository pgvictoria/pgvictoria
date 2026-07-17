\newpage

# CLI reporting engine

The `pgvictoria-cli` report command parses target PostgreSQL configuration parameters and compares them against standard out-of-the-box baselines. This enables rapid detection of configurations that deviate from default values, streamlining performance audits and tuning tasks.

## Overview

The reporting engine supports:
*   **Online scan**: Querying active configurations directly from a live PostgreSQL instance.
*   **Offline scan**: Performing static difference analysis on a local `postgresql.conf` file.
*   **Version override**: Forcing audits against a specific PostgreSQL baseline version (14 through 19).
*   **HTML report**: Exporting audits to clean, professional, high-contrast monochrome HTML documents.
*   **Markdown report**: Exporting audits to Markdown documents.

## Usage

Every report is written to the output path given by `-o`, whatever the format; the command errors if you omit it.

### Format detection
By default, the report format is automatically detected from the output file extension specified via `-o`:
*   Files ending in `.html` will use the **HTML** format.
*   Files ending in `.md` or `.markdown` will use the **Markdown** format.
*   Any other extension (or files without extensions) will default to the **Text** format.

For example, the following command will automatically generate an HTML report because of the `.html` extension:
```bash
pgvictoria-cli -c pgvictoria-cli.conf -o report.html report /etc/postgresql/18/main/postgresql.conf
```

If you want to explicitly override this automatic detection, use the `-f` / `--format` flag (e.g. `-f text`, `-f html`, `-f md`):
```bash
pgvictoria-cli -c pgvictoria-cli.conf -f text -o report.html report /etc/postgresql/18/main/postgresql.conf
```

### Forcing baseline versions
If the configuration file does not declare its version in comments, or if you want to inspect how your configuration compares to a different PostgreSQL release, use the `-pg` (or `--postgresql`) override flag:

```bash
pgvictoria-cli -c pgvictoria-cli.conf -pg 18 -f html -o report.html report /etc/postgresql/18/main/postgresql.conf
```

### Online (server) reports
When run with no configuration file, `report` scans a live PostgreSQL server. The report is written to the `-o` path; choose the format with `-f` (`text` by default, or `html`/`md`):

```bash
pgvictoria-cli -c pgvictoria-cli.conf -f html -o report.html report
```

## Security

`pgvictoria-cli` report features comply with standard safety policies:
*   **No Root Execution**: It refuses to run if invoked by the `root` account to prevent unintentional read/write actions on sensitive system files.
*   **Offline Isolation**: The configuration file reporting mode is completely offline. It reads settings locally and compares them against compiled baseline header definitions without initiating database connections or transmitting configuration parameters.
*   **Buffer Safety**: Command-line arguments (like filenames or version inputs) are parsed and copied using safe `pgvictoria_append()` allocation and size-bounded `snprintf()` calls rather than unsafe raw copying operations.
