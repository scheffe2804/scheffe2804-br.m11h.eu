CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS sources (
  id BIGSERIAL PRIMARY KEY,
  source_uid TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_class TEXT NOT NULL,
  public_url TEXT,
  internal_ref TEXT,
  local_path TEXT,
  status TEXT NOT NULL DEFAULT 'importiert',
  confidentiality TEXT NOT NULL DEFAULT 'intern',
  citation_allowed BOOLEAN NOT NULL DEFAULT FALSE,
  hint_only BOOLEAN NOT NULL DEFAULT FALSE,
  valid_from DATE,
  source_date DATE,
  last_checked_at TIMESTAMPTZ,
  sha256 TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS documents (
  id BIGSERIAL PRIMARY KEY,
  source_id BIGINT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  document_uid TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  original_path TEXT NOT NULL,
  text_path TEXT,
  ocr_path TEXT,
  table_path TEXT,
  sha256 TEXT,
  page_count INTEGER,
  ocr_status TEXT NOT NULL DEFAULT 'ungeprueft',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS chunks (
  id BIGSERIAL PRIMARY KEY,
  document_id BIGINT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  chunk_uid TEXT UNIQUE NOT NULL,
  heading TEXT,
  locator TEXT,
  content TEXT NOT NULL,
  content_tsv tsvector GENERATED ALWAYS AS (to_tsvector('german', content)) STORED,
  embedding vector(384),
  source_class TEXT NOT NULL,
  citation_label TEXT NOT NULL,
  citation_url TEXT,
  internal_ref TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_chunks_tsv ON chunks USING GIN (content_tsv);
CREATE INDEX IF NOT EXISTS idx_sources_class_status ON sources (source_class, status);
CREATE INDEX IF NOT EXISTS idx_documents_source ON documents (source_id);
CREATE INDEX IF NOT EXISTS idx_sources_citation_status ON sources (citation_allowed, status, source_class);
CREATE INDEX IF NOT EXISTS idx_sources_last_checked ON sources (last_checked_at);
CREATE INDEX IF NOT EXISTS idx_documents_sha256 ON documents (sha256);
CREATE INDEX IF NOT EXISTS idx_chunks_document ON chunks (document_id);
CREATE INDEX IF NOT EXISTS idx_chunks_source_class ON chunks (source_class);

CREATE TABLE IF NOT EXISTS queries (
  id BIGSERIAL PRIMARY KEY,
  query_uid TEXT UNIQUE NOT NULL,
  query_type TEXT NOT NULL,
  title TEXT NOT NULL,
  question TEXT NOT NULL,
  selected_source_profile TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'entwurf',
  created_by TEXT NOT NULL DEFAULT 'admin',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS answers (
  id BIGSERIAL PRIMARY KEY,
  query_id BIGINT NOT NULL REFERENCES queries(id) ON DELETE CASCADE,
  answer_uid TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'entwurf',
  html_path TEXT,
  pdf_path TEXT,
  fingerprint TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS answer_statements (
  id BIGSERIAL PRIMARY KEY,
  answer_id BIGINT NOT NULL REFERENCES answers(id) ON DELETE CASCADE,
  section TEXT NOT NULL,
  statement_text TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_answers_query ON answers (query_id);
CREATE INDEX IF NOT EXISTS idx_answers_created_at ON answers (created_at);
CREATE INDEX IF NOT EXISTS idx_answers_export_paths ON answers (html_path, pdf_path);
CREATE INDEX IF NOT EXISTS idx_answer_statements_answer ON answer_statements (answer_id);

CREATE TABLE IF NOT EXISTS answer_citations (
  id BIGSERIAL PRIMARY KEY,
  statement_id BIGINT NOT NULL REFERENCES answer_statements(id) ON DELETE CASCADE,
  chunk_id BIGINT REFERENCES chunks(id) ON DELETE SET NULL,
  citation_label TEXT NOT NULL,
  citation_url TEXT,
  internal_ref TEXT,
  source_class TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_answer_citations_statement ON answer_citations (statement_id);
CREATE INDEX IF NOT EXISTS idx_answer_citations_chunk ON answer_citations (chunk_id);
CREATE INDEX IF NOT EXISTS idx_answer_citations_source_class ON answer_citations (source_class);

CREATE TABLE IF NOT EXISTS cases (
  id BIGSERIAL PRIMARY KEY,
  case_uid TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  topic TEXT,
  status TEXT NOT NULL DEFAULT 'aktiv',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  object_type TEXT,
  object_uid TEXT,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_action_created ON audit_log (action, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_object ON audit_log (object_type, object_uid);
