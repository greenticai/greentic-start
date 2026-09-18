# Reply provenance (`channelData.greenticProvenance` / `channelData.rag`)

A `dw.agent` reply carries a provenance object built from the agent's trail by
`src/agent_provenance.rs`. The same object is written under two keys,
`greenticProvenance` and `rag`.

```json
{
  "version": 1,
  "source": "dw.agent",
  "tools": ["rag_search"],
  "citations": [
    {"tool": "rag_search", "doc": "Refund policy", "excerpt": "…", "score": 0.96},
    {"origin": "knowledge", "doc": "kb/refunds", "title": "Refund policy", "chunkIndex": 3, "score": 0.91}
  ]
}
```

## Citation sources

- **Retrieval tools** (`tool` set). Read from a `tool_call` step's result. They
  include the excerpt text by default, as they always have.
- **Built-in knowledge base** (`"origin": "knowledge"`, no `tool`). Read from the
  runtime's `knowledge_retrieval` trail step (greentic-runner#770). By default
  these carry **identifying fields only**: `doc`, `title`, `sourceFile`,
  `section`, `page`, `chunkIndex` and `score`. They carry **no excerpt text**.

## Setting

| Variable | Default | Effect |
|---|---|---|
| `GREENTIC_PROVENANCE_KNOWLEDGE_EXCERPTS` | off | `1`/`true`/`yes`/`on` adds capped `excerpt` text to built-in knowledge citations |

The setting applies to the whole deployment, because one greentic-start process
serves one bundle. This reply path has no per-tenant settings to read. Turn it on
only when the knowledge base holds text the tenant is willing to have quoted to
end users.

## Caps

These apply to citations from both sources:

- Each excerpt is cut to 500 characters and marked `"excerptTruncated": true`.
- A reply carries at most 20 citations.
- The serialised object is kept under 16 KiB. When it is larger, the
  lowest-ranked citations are dropped and the object is marked
  `"citationsTruncated": true`. Because the object is written under two keys, a
  reply carries at most 32 KiB of provenance.
