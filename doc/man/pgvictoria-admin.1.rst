==============
pgvictoria-admin
==============

-----------------------------------
Administration utility for pgvictoria
-----------------------------------

:Manual section: 1

SYNOPSIS
========

pgvictoria-admin [ -f FILE ] [ COMMAND ]

DESCRIPTION
===========

pgvictoria-admin is an administration utility for pgvictoria.

OPTIONS
=======

-f, --file FILE
  Set the path to a user file

-U, --user USER
  Set the user name

-P, --password PASSWORD
  Set the password for the user

-g, --generate
  Generate a password

-l, --length LENGTH
  Password length

-F, --format FORMAT
  Set the output format (text, json)

-V, --version
  Display version information

-?, --help
  Display help

COMMANDS
========

master-key
  Create or update the master key. The master key will be created in the pgvictoria user home directory under ~/.pgvictoria

user add
  Add a user

user edit
  Update a user

user del
  Remove a user

user ls
  List all users

ENVIRONMENT VARIABLES
=====================

PGVICTORIA_PASSWORD
  Provide either a key for use with the `master-key` command, or a user password for use with the `user add` or `user edit` commands.
  If provided, `pgvictoria-admin` will not ask for the key/password interactively.
  Note that a password provided using the `--password` command line argument will have precedence over this variable.


REPORTING BUGS
==============

pgvictoria is maintained on GitHub at https://github.com/pgvictoria/pgvictoria

COPYRIGHT
=========

pgvictoria is licensed under the 3-clause BSD License.

SEE ALSO
========

pgvictoria-config(1), pgvictoria-cli(1)
