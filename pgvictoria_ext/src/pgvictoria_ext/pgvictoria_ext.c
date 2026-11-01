/*
 * Copyright (C) 2026 The pgvictoria community
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 * be used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* pgvictoria */
#include <postgres.h>
#include <fmgr.h>

#include <pgvictoria_ext.h>
#include <utils/builtins.h>

#include <executor/spi.h>
#include <funcapi.h>

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(pgvictoria_ext_version);

Datum
pgvictoria_ext_version(PG_FUNCTION_ARGS)
{
   Datum version;
   char v[1024];

   memset(&v, 0, sizeof(v));
   snprintf(&v[0], sizeof(v), "%s", VERSION);

   version = CStringGetTextDatum(v);

   PG_RETURN_DATUM(version);
}

PG_FUNCTION_INFO_V1(pgvictoria_ext_slowest_queries);

Datum
pgvictoria_ext_slowest_queries(PG_FUNCTION_ARGS)
{
   FuncCallContext* funcctx;

   if (SRF_IS_FIRSTCALL())
   {
      TupleDesc tupdesc;
      MemoryContext oldcontext;
      SPITupleTable* tuptable;
      uint64 i;
      List* rows = NIL;

      funcctx = SRF_FIRSTCALL_INIT();

      oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

      if (SPI_connect() != SPI_OK_CONNECT)
      {
         ereport(ERROR,
                 (errmsg_internal("pgvictoria_ext_slowest_queries: SPI_connect failed")));
      }

      if (SPI_execute(
             "SELECT current_database()::text AS database, "
             "total_exec_time, query "
             "FROM pg_stat_statements "
             "ORDER BY total_exec_time DESC "
             "LIMIT 10",
             true, 0) != SPI_OK_SELECT)
      {
         SPI_finish();

         ereport(ERROR,
                 (errmsg_internal("pgvictoria_ext_slowest_queries: SPI_execute failed")));
      }
      
      MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

      tupdesc = CreateTemplateTupleDesc(3);

      TupleDescInitEntry(
         tupdesc, (AttrNumber) 1, "database", TEXTOID, -1, 0);

      TupleDescInitEntry(
         tupdesc, (AttrNumber) 2, "total_exec_time", FLOAT8OID, -1, 0);

      TupleDescInitEntry(
         tupdesc, (AttrNumber) 3, "query", TEXTOID, -1, 0);

      funcctx->tuple_desc = BlessTupleDesc(tupdesc);

      tuptable = SPI_tuptable;

      for (i = 0; i < SPI_processed; i++)
      {
         HeapTuple spi_tuple;
         TupleDesc spi_tupdesc;
         Datum values[3];
         bool nulls[3] = {false, false, false};
         HeapTuple tuple;
         bool isnull;

         spi_tuple = tuptable->vals[i];
         spi_tupdesc = tuptable->tupdesc;

         values[0] = SPI_getbinval(
            spi_tuple, spi_tupdesc, 1, &isnull);
         nulls[0] = isnull;

         values[1] = SPI_getbinval(
            spi_tuple, spi_tupdesc, 2, &isnull);
         nulls[1] = isnull;

         values[2] = SPI_getbinval(
            spi_tuple, spi_tupdesc, 3, &isnull);
         nulls[2] = isnull;

         tuple = heap_form_tuple(tupdesc, values, nulls);

         rows = lappend(rows, heap_copytuple(tuple));
      }

      SPI_finish();

      funcctx->user_fctx = rows;

      MemoryContextSwitchTo(oldcontext);
   }

   funcctx = SRF_PERCALL_SETUP();

   {
      List* rows = (List*) funcctx->user_fctx;
      ListCell* cell = list_head(rows);

      if (cell != NULL)
      {
         HeapTuple tuple = (HeapTuple) lfirst(cell);
         Datum result;
         List* rest;

         result = HeapTupleGetDatum(tuple);

         rest = list_delete_first(rows);
         funcctx->user_fctx = rest;

         SRF_RETURN_NEXT(funcctx, result);
      }
      else
      {
         SRF_RETURN_DONE(funcctx);
      }
   }
}