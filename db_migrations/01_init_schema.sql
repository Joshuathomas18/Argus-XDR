-- Argus XDR Database Schema
-- Postgres with pgvector for hybrid graph+vector storage

-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Logs table: Raw security events
CREATE TABLE IF NOT EXISTS logs (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    timestamp TIMESTAMPTZ NOT NULL,
    source_type VARCHAR(50) NOT NULL, -- 'syslog', 'cloud_audit', 'windows_event', 'custom_json'
    source_ip VARCHAR(45), -- Support IPv4 and IPv6
    source_user VARCHAR(255),
    target_resource VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    severity VARCHAR(20) DEFAULT 'info', -- 'critical', 'high', 'medium', 'low', 'info'
    event_type VARCHAR(100),
    raw_data JSONB NOT NULL, -- Original log payload
    normalized_data JSONB, -- Parsed/normalized fields
    metadata JSONB, -- Additional context
    processed BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_source_type ON logs(source_type);
CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity);
CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_logs_source_user ON logs(source_user);
CREATE INDEX IF NOT EXISTS idx_logs_target_resource ON logs(target_resource);
CREATE INDEX IF NOT EXISTS idx_logs_action ON logs(action);

-- Nodes table: Unique entities (IP, User, File, Process, Host, Domain, URL)
CREATE TABLE IF NOT EXISTS nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    entity_type VARCHAR(50) NOT NULL, -- 'IP', 'User', 'Host', 'File', 'Process', 'Domain', 'URL'
    name VARCHAR(255) NOT NULL,
    value VARCHAR(500) NOT NULL, -- Canonical representation (e.g., IP address, username)
    attributes JSONB, -- Type-specific metadata (process_name, file_hash, port, etc.)
    embedding VECTOR(384), -- MiniLM-L6-v2 produces 384-dimensional vectors
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    frequency BIGINT DEFAULT 1, -- How many times this entity appears in logs
    UNIQUE(entity_type, value)
);

CREATE INDEX IF NOT EXISTS idx_nodes_entity_type ON nodes(entity_type);
CREATE INDEX IF NOT EXISTS idx_nodes_value ON nodes(value);
CREATE INDEX IF NOT EXISTS idx_nodes_embedding ON nodes USING ivfflat(embedding vector_cosine_ops)
    WITH (lists = 100);
CREATE INDEX IF NOT EXISTS idx_nodes_frequency ON nodes(frequency DESC);

-- Edges table: Relationships between nodes
CREATE TABLE IF NOT EXISTS edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    source_node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    target_node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    relationship_type VARCHAR(100) NOT NULL, -- 'CONNECTED_TO', 'EXECUTED_BY', 'ACCESSED', 'LOGGED_IN_TO'
    confidence FLOAT DEFAULT 0.5, -- 0.0 to 1.0, higher = more confident
    count BIGINT DEFAULT 1, -- How many times this relationship was observed
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB, -- Edge-specific data (port, protocol, timestamp, etc.)
    UNIQUE(source_node_id, target_node_id, relationship_type)
);

CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(relationship_type);
CREATE INDEX IF NOT EXISTS idx_edges_confidence ON edges(confidence DESC);

-- Embeddings table: Vector representations of log payloads and threat summaries
CREATE TABLE IF NOT EXISTS embeddings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    log_id BIGINT REFERENCES logs(id) ON DELETE CASCADE,
    content_type VARCHAR(50) NOT NULL, -- 'log_event', 'threat_summary', 'knowledge_entry'
    content TEXT NOT NULL, -- Original text that was embedded
    embedding VECTOR(384), -- MiniLM-L6-v2 embedding
    metadata JSONB -- Additional context
);

CREATE INDEX IF NOT EXISTS idx_embeddings_log_id ON embeddings(log_id);
CREATE INDEX IF NOT EXISTS idx_embeddings_content_type ON embeddings(content_type);
CREATE INDEX IF NOT EXISTS idx_embeddings_vector ON embeddings USING ivfflat(embedding vector_cosine_ops)
    WITH (lists = 100);

-- Knowledge entries table: Curated threat intelligence
CREATE TABLE IF NOT EXISTS knowledge_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    category VARCHAR(50) NOT NULL, -- 'attack_pattern', 'detection_rule', 'mitigation_strategy'
    title VARCHAR(255) NOT NULL,
    description TEXT,
    content TEXT NOT NULL, -- Full knowledge entry text
    embedding VECTOR(384), -- MiniLM-L6-v2 embedding for semantic search
    metadata JSONB, -- Tags, references, severity, etc.
    UNIQUE(category, title)
);

CREATE INDEX IF NOT EXISTS idx_knowledge_category ON knowledge_entries(category);
CREATE INDEX IF NOT EXISTS idx_knowledge_embedding ON knowledge_entries USING ivfflat(embedding vector_cosine_ops)
    WITH (lists = 100);

-- Threat alerts/incidents table (for future use)
CREATE TABLE IF NOT EXISTS threats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) DEFAULT 'medium', -- 'critical', 'high', 'medium', 'low'
    status VARCHAR(50) DEFAULT 'open', -- 'open', 'investigating', 'resolved', 'false_positive'
    related_logs BIGINT[] DEFAULT ARRAY[]::BIGINT[], -- Array of log IDs
    related_nodes UUID[] DEFAULT ARRAY[]::UUID[], -- Array of node IDs involved
    metadata JSONB,
    analyst_notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
CREATE INDEX IF NOT EXISTS idx_threats_created_at ON threats(created_at DESC);

-- Audit log for tracking changes
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    action VARCHAR(100) NOT NULL, -- 'INSERT', 'UPDATE', 'DELETE'
    table_name VARCHAR(100) NOT NULL,
    record_id TEXT,
    changes JSONB,
    user_id VARCHAR(100),
    ip_address VARCHAR(45)
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
