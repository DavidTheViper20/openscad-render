# OpenSCAD Render Service

## Endpoints

### GET /health
Returns "ok".

### POST /render
Body (JSON):
{
  "code": "<OpenSCAD code>",
  "format": "stl"
}

Returns raw STL bytes with Content-Type: application/sla

Optional auth:
Set env OPENSCAD_RENDER_TOKEN and call with:
Authorization: Bearer <token>
