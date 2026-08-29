# Decision records

Decisions where a reasonable engineer would have asked "why that way?" — and
where the answer is not obvious from the code.

| # | Decision |
|---|---|
| [0001](0001-python-over-rust.md) | Python for the core, not Rust, with zero runtime dependencies |
| [0002](0002-deterministic-ids.md) | Content-addressed ids, and what is deliberately excluded from them |
| [0003](0003-claims-versus-attestations.md) | Claims and attestations are separate records |
| [0004](0004-mcp-without-sdk.md) | The MCP server speaks the protocol directly |
| [0005](0005-carver-fallback.md) | A bounded extraction fallback when binwalk is absent |
| [0006](0006-narrow-nl-without-a-model.md) | The natural-language interface contains no language model |
| [0007](0007-emulation-is-opt-in.md) | Emulation never runs implicitly |
