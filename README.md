# Argus XDR

Multi-stage, AI-driven XDR (Extended Detection and Response) pipeline that ingests security logs, maps them into a Graph+Vector hybrid database, calculates deterministic threat paths, and executes agentic mitigation.

## Architecture

- **Database**: Supabase with Postgres + pgvector for hybrid graph+vector storage
- **RAG Pipeline**: Hybrid search combining topological graph queries and semantic search
- **Knowledge Base**: Curated threat intelligence with 12+ attack patterns and mitigation strategies
- **API**: FastAPI backend with endpoints for log ingestion, threat analysis, and graph queries

## Quick Start

### 1. Clone and Setup

```bash
cd Argus-XDR

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your Supabase credentials
# SUPABASE_URL=https://your-project.supabase.co
# SUPABASE_KEY=your-anon-key
```

### 3. Setup Database

```bash
# Apply migrations to Supabase
# 1. Go to Supabase console -> SQL Editor
# 2. Create a new query
# 3. Copy contents of db_migrations/01_init_schema.sql
# 4. Execute the query
```

### 4. Run Application

```bash
# Start the server
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Server will be available at http://localhost:8000
# API docs at http://localhost:8000/docs
# OpenAPI spec at http://localhost:8000/openapi.json
```

## API Endpoints

### Health Check
- `GET /health` - Service health status
- `GET /ready` - Readiness check with component verification

### Log Ingestion
- `POST /api/ingest/logs` - Ingest batch security logs
- `POST /api/ingest/cloud-audit` - Ingest cloud provider audit logs
- `GET /api/ingest/status` - Ingestion pipeline status

### Threat Analysis
- `POST /api/threats/analyze` - Analyze security alert using hybrid retrieval
- `GET /api/threats/patterns/{threat_id}` - Get similar past threats
- `GET /api/threats/graph/{entity_id}` - Get entity's connected graph
- `GET /api/threats/entities` - List all threat entities

## Example Usage

### Ingest Logs

```bash
curl -X POST http://localhost:8000/api/ingest/logs \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      {
        "timestamp": "2024-04-13T10:00:00Z",
        "event_type": "login",
        "severity": "info",
        "source_ip": "192.168.1.100",
        "source_user": "admin",
        "target_resource": "server1",
        "action": "login",
        "metadata": {}
      }
    ],
    "source_type": "custom_json"
  }'
```

### Analyze Threat

```bash
curl -X POST http://localhost:8000/api/threats/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What is suspicious activity from IP 192.168.1.100?",
    "top_k": 5,
    "include_topological": true
  }'
```

## Project Structure

```
argus-xdr/
├── db_migrations/
│   └── 01_init_schema.sql          # Database schema with pgvector
├── backend/
│   ├── core/
│   │   ├── config.py               # Configuration management
│   │   └── database.py             # Supabase client & operations
│   ├── rag/
│   │   ├── embedder.py             # Vector embeddings (MiniLM)
│   │   ├── retriever.py            # Hybrid search with RRF
│   │   └── knowledge.py            # Threat intelligence KB
│   ├── pipeline/
│   │   ├── parser.py               # Log parsing & normalization
│   │   └── graph_builder.py        # Entity extraction & graph construction
│   ├── api/
│   │   ├── routes_ingest.py        # Log ingestion endpoints
│   │   └── routes_threats.py       # Threat analysis endpoints
│   └── main.py                     # FastAPI application
├── tests/                          # Unit & integration tests
├── requirements.txt                # Python dependencies
├── .env.example                    # Configuration template
└── README.md                       # This file
```

## Key Features

### Database Architecture
- **Logs**: Raw security events with structured JSON
- **Nodes**: Unique entities (IP, User, Host, File, Process, Domain, URL) with embeddings
- **Edges**: Relationships between entities with confidence scores
- **Embeddings**: Vector representations of log payloads and threat summaries
- **Knowledge**: Curated threat intelligence entries with embeddings

### RAG Pipeline
1. **Topological Search**: SQL queries on graph structure
2. **Semantic Search**: pgvector similarity queries
3. **Keyword Search**: BM25-based full-text search
4. **RRF Merging**: Reciprocal Rank Fusion to combine results
5. **Cross-Encoder Reranking**: Final ranking with cross-encoder model

### Knowledge Base
- 12+ attack patterns (lateral movement, exfiltration, privilege escalation, persistence, defense evasion)
- 2+ detection rules for identifying suspicious activities
- 2+ mitigation strategies for containment and hardening

## Future Enhancements (Phase 5)

- Agent orchestrator with ReAct loop
- Graph traversal algorithms (BFS, Dijkstra) for attack path detection
- LLM-based threat summarization and reporting
- Automated response actions
- Dashboard and visualization

## Development

### Run Tests

```bash
pytest tests/ -v
```

### Code Quality

```bash
# Format code
black backend/

# Sort imports
isort backend/

# Lint
flake8 backend/
```

## Security Notes

- Keep `.env` file out of version control
- Use service role key only in secure backend environments
- Implement proper authentication before production deployment
- Enable network segmentation for database access
- Rotate API keys regularly

## License

Proprietary - Argus XDR Security Pipeline

## Support

For issues and questions, contact the security team.
