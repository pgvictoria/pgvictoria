# PostgreSQL Configuration Reporting Tool

A tool to convert PostgreSQL configurations into C header files with embedded JSON. It generates the official baseline configurations for PostgreSQL 14–18, allowing pgvictoria to compare active settings against default values.

## Usage

The script `pg_config_report.py` supports several modes of operation.

### 1. Generate All Baselines (Docker)

To automatically generate C headers for all supported PostgreSQL versions (14, 15, 16, 17, 18) using Docker containers:

```bash
python pg_config_report.py
```
*Note: This requires a container engine (Docker or Podman) to be running. It will pull the official PostgreSQL images, extract the settings, and save the headers to `src/include/`.*

### 2. Generate Specific Version Baseline (Docker)

To generate a baseline for a specific version:

```bash
python pg_config_report.py --version 15
```

### 3. Process a Manual Configuration File

If you have a `postgresql.conf` or the output of `SHOW ALL` in a file:

```bash
python pg_config_report.py --input postgresql.conf --version 15 --output pg15.h
```

### 4. Fetch from a Live Instance (psql)

To capture settings from a live PostgreSQL instance accessible via `psql`:

```bash
python pg_config_report.py --psql --version 15
```

## How it Works

1.  **Extraction**: The script either reads a file, runs `psql -c "SHOW ALL"`, or starts a temporary Docker container to run the command.
2.  **Parsing**: It handles both standard `.conf` file formats (`key = value`) and the tabular output format from `psql`'s `SHOW ALL`.
3.  **JSON Generation**: The parameters are converted into a JSON object.
4.  **C Header Generation**: The JSON is escaped and embedded as a `static const char*` string in a C header file with appropriate header guards.
