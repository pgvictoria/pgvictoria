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
#include <deque.h>
#include <html_report.h>
#include <utils.h>

/* system */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>

int
pgvictoria_generate_html_report(const char* output_html_path, int version, struct deque* items, const char* scope_label, const char* scope_value)
{
   pgvictoria_mkdir_parent(output_html_path);

   /* Create HTML Document */
   htmlDocPtr doc = htmlNewDoc(NULL, NULL);
   if (!doc)
   {
      return 1;
   }

   /* Create <html> root node */
   xmlNodePtr html = xmlNewNode(NULL, BAD_CAST "html");
   xmlDocSetRootElement(doc, html);
   xmlNewProp(html, BAD_CAST "lang", BAD_CAST "en");

   /* Create <head> and <body> */
   xmlNodePtr head_node = xmlNewChild(html, NULL, BAD_CAST "head", NULL);
   xmlNodePtr body = xmlNewChild(html, NULL, BAD_CAST "body", NULL);

   /* Head elements */
   xmlNodePtr meta_charset = xmlNewChild(head_node, NULL, BAD_CAST "meta", NULL);
   xmlNewProp(meta_charset, BAD_CAST "charset", BAD_CAST "UTF-8");
   xmlNodePtr meta_vp = xmlNewChild(head_node, NULL, BAD_CAST "meta", NULL);
   xmlNewProp(meta_vp, BAD_CAST "name", BAD_CAST "viewport");
   xmlNewProp(meta_vp, BAD_CAST "content", BAD_CAST "width=device-width, initial-scale=1.0");

   xmlNewChild(head_node, NULL, BAD_CAST "title", BAD_CAST "pgvictoria Configuration Report");

   /* Monochrome Premium CSS Styling */
   const char* style_content =
      "body {\n"
      "  font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif;\n"
      "  background-color: #ffffff;\n"
      "  color: #111111;\n"
      "  margin: 0;\n"
      "  padding: 40px 20px;\n"
      "  line-height: 1.5;\n"
      "}\n"
      ".container {\n"
      "  max-width: 960px;\n"
      "  margin: 0 auto;\n"
      "}\n"
      "h1 {\n"
      "  font-size: 28px;\n"
      "  font-weight: 700;\n"
      "  margin-bottom: 8px;\n"
      "  border-bottom: 2px solid #111111;\n"
      "  padding-bottom: 12px;\n"
      "  text-transform: uppercase;\n"
      "  letter-spacing: 0.5px;\n"
      "}\n"
      "table.metadata {\n"
      "  width: auto;\n"
      "  margin: 0 0 30px 0;\n"
      "  font-size: 14px;\n"
      "  color: #666666;\n"
      "}\n"
      "table.metadata td {\n"
      "  padding: 4px 16px 4px 0;\n"
      "  border-bottom: none;\n"
      "}\n"
      "table.metadata td:first-child {\n"
      "  font-weight: 700;\n"
      "  color: #111111;\n"
      "}\n"
      "table {\n"
      "  width: 100%;\n"
      "  border-collapse: collapse;\n"
      "  margin-top: 20px;\n"
      "  font-size: 14px;\n"
      "}\n"
      "th {\n"
      "  text-align: left;\n"
      "  padding: 12px 10px;\n"
      "  border-bottom: 2px solid #111111;\n"
      "  font-weight: 700;\n"
      "  text-transform: uppercase;\n"
      "  font-size: 12px;\n"
      "  color: #111111;\n"
      "}\n"
      "td {\n"
      "  padding: 12px 10px;\n"
      "  border-bottom: 1px solid #e5e5e5;\n"
      "  vertical-align: middle;\n"
      "  word-break: break-all;\n"
      "}\n"
      "tr:nth-child(even) td {\n"
      "  background-color: #fafafa;\n"
      "}\n"
      "tr:hover td {\n"
      "  background-color: #f0f0f0;\n"
      "}\n"
      ".badge {\n"
      "  display: inline-block;\n"
      "  font-size: 11px;\n"
      "  font-weight: 700;\n"
      "  padding: 4px 8px;\n"
      "  text-transform: uppercase;\n"
      "  border: 1px solid #111111;\n"
      "  border-radius: 0;\n"
      "  letter-spacing: 0.5px;\n"
      "}\n"
      ".badge-default {\n"
      "  background-color: #f0f0f0;\n"
      "  color: #333333;\n"
      "  border-color: #cccccc;\n"
      "}\n"
      ".badge-modified {\n"
      "  background-color: #333333;\n"
      "  color: #ffffff;\n"
      "  border-color: #333333;\n"
      "}\n"
      ".badge-custom {\n"
      "  background-color: #ffffff;\n"
      "  color: #111111;\n"
      "  border-color: #111111;\n"
      "  border-style: dashed;\n"
      "}\n"
      "@media print {\n"
      "  body {\n"
      "    padding: 0;\n"
      "  }\n"
      "  table {\n"
      "    page-break-inside: auto;\n"
      "  }\n"
      "  tr {\n"
      "    page-break-inside: avoid;\n"
      "    page-break-after: auto;\n"
      "  }\n"
      "}\n";

   xmlNewChild(head_node, NULL, BAD_CAST "style", BAD_CAST style_content);

   /* Body elements container */
   xmlNodePtr container = xmlNewChild(body, NULL, BAD_CAST "div", NULL);
   xmlNewProp(container, BAD_CAST "class", BAD_CAST "container");

   /* Title */
   char title_text[256];
   pgvictoria_snprintf(title_text, sizeof(title_text), "PostgreSQL %d Configuration Difference Report", version);
   xmlNewChild(container, NULL, BAD_CAST "h1", BAD_CAST title_text);

   /* Metadata block: a label/value table describing what was audited */
   xmlNodePtr metadata_table = xmlNewChild(container, NULL, BAD_CAST "table", NULL);
   xmlNewProp(metadata_table, BAD_CAST "class", BAD_CAST "metadata");
   xmlNodePtr metadata_body = xmlNewChild(metadata_table, NULL, BAD_CAST "tbody", NULL);

   if (scope_label && scope_value)
   {
      xmlNodePtr scope_row = xmlNewChild(metadata_body, NULL, BAD_CAST "tr", NULL);
      xmlNewChild(scope_row, NULL, BAD_CAST "td", BAD_CAST scope_label);
      xmlNewChild(scope_row, NULL, BAD_CAST "td", BAD_CAST scope_value);
   }

   char baseline_meta[128];
   pgvictoria_snprintf(baseline_meta, sizeof(baseline_meta), "PostgreSQL %d", version);
   xmlNodePtr version_row = xmlNewChild(metadata_body, NULL, BAD_CAST "tr", NULL);
   xmlNewChild(version_row, NULL, BAD_CAST "td", BAD_CAST "Version");
   xmlNewChild(version_row, NULL, BAD_CAST "td", BAD_CAST baseline_meta);

   char* os_name = NULL;
   int k_major = 0, k_minor = 0, k_patch = 0;
   if (pgvictoria_os_kernel_version(&os_name, &k_major, &k_minor, &k_patch) == 0)
   {
      char os_meta[256];
      pgvictoria_snprintf(os_meta, sizeof(os_meta), "%s %d.%d.%d", os_name, k_major, k_minor, k_patch);
      xmlNodePtr system_row = xmlNewChild(metadata_body, NULL, BAD_CAST "tr", NULL);
      xmlNewChild(system_row, NULL, BAD_CAST "td", BAD_CAST "System");
      xmlNewChild(system_row, NULL, BAD_CAST "td", BAD_CAST os_meta);
      free(os_name);
   }

   /* Table structure */
   xmlNodePtr table = xmlNewChild(container, NULL, BAD_CAST "table", NULL);
   xmlNodePtr thead = xmlNewChild(table, NULL, BAD_CAST "thead", NULL);
   xmlNodePtr tbody = xmlNewChild(table, NULL, BAD_CAST "tbody", NULL);

   xmlNodePtr thr = xmlNewChild(thead, NULL, BAD_CAST "tr", NULL);
   xmlNewChild(thr, NULL, BAD_CAST "th", BAD_CAST "Configuration Key");
   xmlNewChild(thr, NULL, BAD_CAST "th", BAD_CAST "Baseline Default");
   xmlNewChild(thr, NULL, BAD_CAST "th", BAD_CAST "Current Value");
   xmlNewChild(thr, NULL, BAD_CAST "th", BAD_CAST "Status");

   /* Populate table rows from diff list */
   struct deque_iterator* it = NULL;
   pgvictoria_deque_iterator_create(items, &it);
   while (pgvictoria_deque_iterator_next(it))
   {
      struct pgvictoria_diff_item* curr = (struct pgvictoria_diff_item*)it->value->data;

      const char* disp_key = curr->key;
      const char* def_val = curr->baseline_val;
      const char* value = curr->current_val;
      const char* status_text = curr->status;
      const char* badge_class = "badge badge-custom";

      if (strcmp(status_text, "Default") == 0)
      {
         badge_class = "badge badge-default";
      }
      else if (strcmp(status_text, "Modified") == 0)
      {
         badge_class = "badge badge-modified";
      }

      /* Append row to table */
      xmlNodePtr tr = xmlNewChild(tbody, NULL, BAD_CAST "tr", NULL);
      xmlNewChild(tr, NULL, BAD_CAST "td", BAD_CAST disp_key);
      xmlNewChild(tr, NULL, BAD_CAST "td", BAD_CAST def_val);
      xmlNewChild(tr, NULL, BAD_CAST "td", BAD_CAST value);
      xmlNodePtr td_status = xmlNewChild(tr, NULL, BAD_CAST "td", NULL);
      xmlNodePtr span_badge = xmlNewChild(td_status, NULL, BAD_CAST "span", BAD_CAST status_text);
      xmlNewProp(span_badge, BAD_CAST "class", BAD_CAST badge_class);
   }
   pgvictoria_deque_iterator_destroy(it);

   /* Save document to file */
   int saved_bytes = htmlSaveFileEnc(output_html_path, doc, "UTF-8");
   xmlFreeDoc(doc);

   if (saved_bytes < 0)
   {
      return 1;
   }

   printf("Report successfully generated to %s\n", output_html_path);
   return 0;
}
