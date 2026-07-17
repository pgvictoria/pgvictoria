==============
pgvictoria-cli
==============

--------------------------------------
Command line interface for pgvictoria
--------------------------------------

:Manual section: 1

SYNOPSIS
========

pgvictoria-cli [ -c CONFIG_FILE ] [ -u USERS_FILE ] [ -pg VERSION ] [ -H HOST ] [ -P PORT ] [ -U USER ] [ -W PASSWORD ] [ -f FORMAT ] [ -t TYPE ] [ -o OUTPUT_FILE ] [ -V ] [ -? ] [ COMMAND ]

DESCRIPTION
===========

pgvictoria-cli is a command-line interface utility for pgvictoria to run performance configuration comparison scans. It compares PostgreSQL server configurations against default version baselines.

OPTIONS
=======

-c, --config FILE
  Set the path to the pgvictoria.conf configuration file. Default is /etc/pgvictoria/pgvictoria.conf.

-u, --users FILE
  Set the path to the pgvictoria_users.conf configuration file. Default is /etc/pgvictoria/pgvictoria_users.conf.

-pg, --postgresql VERSION
  Override the PostgreSQL baseline version to compare against. Valid range is 14 to 19.

-H, --host HOST
  Set the host name or IP address of the target PostgreSQL server. Default is 127.0.0.1.

-P, --port PORT
  Set the port number of the target PostgreSQL server. Default is 5432.

-U, --user USER
  Set the database user name. Default is postgres.

-W, --password PASSWORD
  Set the database password for authentication.

-f, --format FORMAT
  Select the report format: text (default), html, or md (markdown is accepted as a synonym for md). If omitted, the format is automatically detected from the output file extension (.html -> HTML, .md/.markdown -> Markdown, other -> Text). Honored in both online and offline modes.

-t, --type TYPE
  Select which settings to list: changed (default) shows only settings whose value differs from the version baseline, while full lists every setting. Honored in both online and offline modes.

-o, --output OUTPUT_FILE
  Write the report to OUTPUT_FILE (its parent directory is created if needed). Honored in both modes and required for every format; the report command errors without it.

-V, --version
  Display version information.

-?, --help
  Display help.

COMMANDS
========

report [input_config_file]
  Generate a configuration report. The -f (format) and -o (output) flags apply identically to both modes.
  With no positional argument, it performs a connection-based live scan of the target PostgreSQL server (SHOW ALL).
  With one argument [input_config_file], it parses that configuration file statically.
  The report is always written to the -o path (required); choose the format with -f (text by default, or html/md).

EXAMPLES
========

Perform a live configuration report scan:

  $ pgvictoria-cli -c pgvictoria-cli.conf -o report.txt report

Perform a static config file comparison:

  $ pgvictoria-cli -c pgvictoria-cli.conf -o report.txt report /etc/postgresql/18/main/postgresql.conf

Generate an HTML configuration report for PostgreSQL 18:

  $ pgvictoria-cli -c pgvictoria-cli.conf -pg 18 -f html -o diff_report.html report /etc/postgresql/18/main/postgresql.conf

REPORTING BUGS
==============

pgvictoria is under active development. Please report any bugs at
https://github.com/pgvictoria/pgvictoria/issues

COPYRIGHT
=========

pgvictoria is licensed under the 3-clause BSD License.

SEE ALSO
========

pgvictoria(1), pgvictoria-config(1)
