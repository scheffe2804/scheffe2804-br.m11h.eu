-- Idempotent operational indexes for existing and future BR-Wissen databases.
-- These support guards, answer/export views, audits and restore validation.

CREATE INDEX IF NOT EXISTS idx_sources_citation_status ON sources (citation_allowed, status, source_class);
CREATE INDEX IF NOT EXISTS idx_sources_last_checked ON sources (last_checked_at);
CREATE INDEX IF NOT EXISTS idx_documents_sha256 ON documents (sha256);
CREATE INDEX IF NOT EXISTS idx_chunks_document ON chunks (document_id);
CREATE INDEX IF NOT EXISTS idx_chunks_source_class ON chunks (source_class);
CREATE INDEX IF NOT EXISTS idx_answers_query ON answers (query_id);
CREATE INDEX IF NOT EXISTS idx_answers_created_at ON answers (created_at);
CREATE INDEX IF NOT EXISTS idx_answers_export_paths ON answers (html_path, pdf_path);
CREATE INDEX IF NOT EXISTS idx_answer_statements_answer ON answer_statements (answer_id);
CREATE INDEX IF NOT EXISTS idx_answer_citations_statement ON answer_citations (statement_id);
CREATE INDEX IF NOT EXISTS idx_answer_citations_chunk ON answer_citations (chunk_id);
CREATE INDEX IF NOT EXISTS idx_answer_citations_source_class ON answer_citations (source_class);
CREATE INDEX IF NOT EXISTS idx_audit_log_action_created ON audit_log (action, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_object ON audit_log (object_type, object_uid);
