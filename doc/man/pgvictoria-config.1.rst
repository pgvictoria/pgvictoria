=================
pgvictoria-config
=================

--------------------------------------
Configuration utility for pgvictoria
--------------------------------------

:Manual section: 1

SYNOPSIS
========

pgvictoria-config [ -o OUTPUT_FILE ] [ -q ] [ -F ] [ -V ] [ -? ] [ COMMAND ]

DESCRIPTION
===========

pgvictoria-config is a command-line utility used to generate and manage the configuration file for pgvictoria.

OPTIONS
=======

-o, --output FILE
  Set the output file path. Default is ./pgvictoria.conf.

-q, --quiet
  Quiet mode. Generate default configuration without interactive prompts (for init).

-F, --force
  Force overwrite if the output file already exists.

-V, --version
  Display version information.

-?, --help
  Display help.

COMMANDS
========

init
  Generate a new configuration file. By default, it runs interactively, asking for basic setup information.

get <file> <section> <key>
  Retrieve a configuration value from the specified file.

set <file> <section> <key> <value>
  Set or update a configuration value in the specified file. The file is updated atomically.

del <file> <section> [key]
  Delete a key or an entire section from the specified file.

ls <file> [section]
  List all sections in the file, or list all keys in a specific section.

EXAMPLES
========

Generate a new configuration interactively:

  $ pgvictoria-config init

Generate a default configuration without prompts:

  $ pgvictoria-config -q -o my_pgvictoria.conf init

Update the log level:

  $ pgvictoria-config set pgvictoria.conf pgvictoria log_level debug

List all sections:

  $ pgvictoria-config ls pgvictoria.conf

REPORTING BUGS
==============

pgvictoria is under active development. Please report any bugs at
https://github.com/pgvictoria/pgvictoria/issues

COPYRIGHT
=========

pgvictoria is licensed under the 3-clause BSD License.

SEE ALSO
========

pgvictoria(1)
