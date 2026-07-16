\newpage

# Quick start

Make sure that [**pgvictoria**][pgvictoria] is installed and in your path by using `pgvictoria-cli -?`. You should see

``` console
pgvictoria-cli 0.1.0
  Command line utility for pgvictoria

Usage:
  pgvictoria-cli [ OPTIONS ] report [ CONFIG_FILE ]

Commands:
  report                       Generate a configuration report against the version baseline
                                 no arguments  - scan the live server (online mode)
                                 CONFIG_FILE   - compare a postgresql.conf file (offline mode)

Options:
  -c, --config CONFIG_FILE      Set the path to the pgvictoria.conf file
  -u, --users USERS_FILE        Set the path to the pgvictoria_users.conf file
  -H, --host HOST               Set the PostgreSQL host (default: 127.0.0.1)
  -P, --port PORT               Set the PostgreSQL port (default: 5432)
  -U, --user USER               Set the database user (default: postgres)
  -W, --password PASSWORD       Set the database password
  -pg, --postgresql VERSION     Override the baseline version to compare against (14-19)
  -f, --format FORMAT           Report format: text|html|md (default: text)
  -o, --output OUTPUT_FILE      Write the report to OUTPUT_FILE (required)
  -V, --version                 Display version information
  -?, --help                    Display help

pgvictoria: https://pgvictoria.github.io/
Report bugs: https://github.com/pgvictoria/pgvictoria/issues
```

If you encounter any issues following the above steps, you can refer to the **Installation** chapter to see how to install or compile [**pgvictoria**][pgvictoria] on your system.

## Configuration

Lets create a simple configuration file called `pgvictoria.conf` with the content

``` ini
[pgvictoria]
host = localhost

log_type = console
log_level = info

unix_socket_dir = /tmp/

[primary]
host = localhost
port = 5432
user = postgres
```

In our main section called `[pgvictoria]` we setup [**pgvictoria**][pgvictoria] to bind to `localhost`. Logging will be performed at `info` level on the console. Last we specify the location of the `unix_socket_dir` used for management operations.

Next we create a section called `[primary]` which has the information about our [PostgreSQL][postgresql] instance. In this case it is running on `localhost` on port `5432` and we will use the `postgres` user account to connect.

The configuration file can also be generated with the `pgvictoria-config` tool - see the **Configuration generator** chapter.

See the **Configuration** chapter for all configuration options.

## Generating a report

We can now generate our first report against the live [PostgreSQL][postgresql] instance

``` sh
pgvictoria-cli -c pgvictoria.conf -o report.txt report
```

The database password can be given with the `-W` flag, or through the `PGPASSWORD` environment variable, like

``` sh
PGPASSWORD=secretpassword pgvictoria-cli -c pgvictoria.conf -o report.txt report
```

The report in `report.txt` shows the settings of the server compared against the default out-of-the-box configuration for that PostgreSQL version.

If you don't have a configuration file the connection information can be given on the command line instead, like

``` sh
pgvictoria-cli -H localhost -P 5432 -U postgres -o report.txt report
```

## HTML and Markdown reports

The report format is selected with the `-f` flag, so an HTML report is done by

``` sh
pgvictoria-cli -c pgvictoria.conf -f html -o report.html report
```

and a Markdown report by

``` sh
pgvictoria-cli -c pgvictoria.conf -f md -o report.md report
```

## Reporting on a configuration file

[**pgvictoria**][pgvictoria] can also compare a `postgresql.conf` file directly without connecting to a server, by passing the path to the file

``` sh
pgvictoria-cli -c pgvictoria.conf -o report.txt report /etc/postgresql/18/main/postgresql.conf
```

If the file does not declare its PostgreSQL version, or if you want to compare against a different release, the baseline version can be forced with the `-pg` flag

``` sh
pgvictoria-cli -c pgvictoria.conf -pg 18 -o report.txt report /etc/postgresql/18/main/postgresql.conf
```

See the **CLI reporting engine** chapter for more information.

## Administration

[**pgvictoria**][pgvictoria] has an administration tool called `pgvictoria-admin`, which is used to manage user registrations and encrypted passwords for target servers.

First, create or update the master key file:
``` sh
pgvictoria-admin master-key
```

Next, add a user and configure their password (which will be encrypted using the master key and written to `pgvictoria_users.conf`):
``` sh
pgvictoria-admin -f pgvictoria_users.conf -U username user add
```

This users file can then be supplied to `pgvictoria-cli` using the `-u` or `--users` flag:
``` sh
pgvictoria-cli -u pgvictoria_users.conf -c pgvictoria.conf -o report.txt report
```

## Closing

The [**pgvictoria**][pgvictoria] community hopes that you find
the project interesting.

Feel free to

* [Ask a question][ask]
* [Raise an issue][issue]
* [Submit a feature request][request]
* [Write a code submission][submission]

All contributions are most welcome !

Please, consult our [Code of Conduct][conduct] policies for interacting in our
community.

Consider giving the project a [star][star] on
[GitHub](https://github.com/pgvictoria/pgvictoria/) if you find it useful. And, feel free to follow
the project on X as well.
