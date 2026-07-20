# gitea — orca plugin

First-party [orca](https://github.com/argyle-labs/orca) plugin for
[Gitea](https://gitea.io): the **full Gitea REST API** as `gitea.*` tools, plus
**dual-substrate deploy** (LXC or Docker) and **substrate-portable
backup/restore** wrapping `gitea dump`.

## Surface

- **`gitea.*` REST surface** — 279 tools generated at build time by
  `plugin_toolkit_build::openapi` + `surface::openapi` from the vendored spec
  (`specs/gitea.openapi.json`). Covers repos, orgs, users, teams, issues, PRs,
  mirrors, actions/runners, packages, admin, etc. Reads are `role = "read"`;
  writes (POST/PUT/PATCH/DELETE) are `data_mutation = true` + `role = "admin"`.
- **`gitea.{list,detail,create,update,delete}`** — endpoint registry CRUD
  (`#[endpoint_resource]`). Register an instance with its base URL + a `#[secret]`
  API token; every `gitea.*` call takes an `--endpoint` and resolves it here.
- **`gitea.deploy`** — `substrate = lxc | docker`. Dispatches to a
  `GiteaSubstrate` provider: the LXC provider drives the proxmox plugin (create
  LXC, nesting) + Gitea/Postgres; the Docker provider drives the docker/dockge
  plugin (`gitea/gitea` + `postgres` compose). *(Provider execution wiring over
  `plugin.invoke` is landing incrementally; the trait + dispatch + spec are the
  stable seam.)*
- **`gitea.backup` / `gitea.restore`** — wrap `gitea dump`; the archive is
  **portable between substrates** (an LXC dump restores into a Docker deploy and
  vice-versa), which also makes LXC↔Docker migration a backup+restore.

## ABI

Subprocess/UDS plugin (`serve_tool_plugin!` in `src/main.rs`) — orca's loader
spawns the `[[bin]]` and speaks the wire protocol over a Unix socket. No cdylib.

## Refreshing the vendored spec

Gitea ships **Swagger 2.0** at `/swagger.v1.json`; progenitor needs OpenAPI 3.0,
and a few constructs need normalizing beyond what the orca toolkit does today:

```sh
curl -s https://gitea.example/swagger.v1.json > specs/gitea.swagger2.json
npx -y swagger2openapi@7 specs/gitea.swagger2.json -o specs/gitea.openapi.json
python3 spec-tools/prep_spec.py specs/gitea.openapi.json
cargo build
```

`spec-tools/prep_spec.py` applies transforms the orca normalizer doesn't (yet) —
each is commented with a `TODO(orca)` pointing at the proper normalizer fix:
- multipart request bodies (component + paths) → `application/json` (binary→string),
  so the delegated-http profile never emits `Into<reqwest::Body>`;
- divergent multi-`2xx` responses collapsed to the representative bodied one;
- typed 4xx/5xx/`default` error responses stripped (they map to
  `UnexpectedResponse`; no operation is lost) to satisfy progenitor's
  single-response-type-per-bucket assertion — which fires because the normalizer
  doesn't resolve response-level `$ref`s before merging buckets.

Once those land in the orca toolkit (and the toolkit is cut as an independent
versioned release), this prep script retires.

## Development

Builds against the local in-tree toolkit via the `[patch]` in `.cargo/config.toml`
(expects the orca repo checked out at `../orca`). Without the patch,
`plugin-toolkit` resolves from the git branch pinned in `Cargo.toml` — soon to be
a pinned version from the Gitea Cargo registry.
