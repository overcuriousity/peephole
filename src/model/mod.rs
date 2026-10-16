//! Pure code shared by the store and the layers above it (`scan`, `trap`):
//! the nmap XML and what is extracted from it, request fingerprints, the
//! retry schedule and the decoys' fixed tables. No I/O, and nothing here
//! uses `admin`, `scan` or `trap`, so `store` can use it without them.
pub mod facts;
pub mod hostkeys;
pub mod ja4h;
pub mod llm;
pub mod mcp;
pub mod nmap_xml;
pub mod retry;
pub mod shape;
pub mod webshell;
