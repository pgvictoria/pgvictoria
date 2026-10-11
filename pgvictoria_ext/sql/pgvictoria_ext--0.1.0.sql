CREATE FUNCTION pgvictoria_ext_version()
RETURNS text
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FUNCTION pgvictoria_ext_slowest_queries()
RETURNS TABLE (
    database text,
    total_exec_time double precision,
    query text
)
AS 'MODULE_PATHNAME',
   'pgvictoria_ext_slowest_queries'
LANGUAGE C;