-- What tied a paths edge (MIK-635), written by the campaign pass with
-- campaign_edges and replaced with it; node-local like it, never exported.
-- campaign_edge_shapes: the shared shapes the score counted, the rarest
-- store::campaigns::EDGE_SHAPES_MAX of them, with their document frequency
-- in that pass. campaign_edge_tls: the (JA4, JA4H) pairs both IPs sent.
-- a, b: campaign_edges.a, .b (ip ids).
CREATE TABLE campaign_edge_shapes (
  a INTEGER NOT NULL, b INTEGER NOT NULL,
  shape INTEGER NOT NULL,
  df INTEGER NOT NULL,
  PRIMARY KEY (a, b, shape)
) WITHOUT ROWID;
CREATE TABLE campaign_edge_tls (
  a INTEGER NOT NULL, b INTEGER NOT NULL,
  ja4 TEXT NOT NULL, ja4h TEXT NOT NULL,
  PRIMARY KEY (a, b, ja4, ja4h)
) WITHOUT ROWID;
-- The next pass fills them, whether or not the inputs changed.
DELETE FROM settings WHERE key = 'campaigns.signature';
