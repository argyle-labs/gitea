#!/usr/bin/env python3
"""Prep the vendored Gitea OpenAPI spec for progenitor codegen.

Gitea ships Swagger 2.0 at /swagger.v1.json. Convert to OpenAPI 3.0 first:
    curl -s https://gitea.example/swagger.v1.json > specs/gitea.swagger2.json
    npx -y swagger2openapi@7 specs/gitea.swagger2.json -o specs/gitea.openapi.json
    python3 spec-tools/prep_spec.py specs/gitea.openapi.json

What this fixes that the orca toolkit normalizer does NOT (yet):
  The toolkit's `openapi::normalize::rewrite_multipart_to_octet_stream` walks
  `paths` only. Gitea also defines a REUSABLE multipart request body under
  `components/requestBodies` (issueCreateIssueCommentAttachment), which
  progenitor rejects ("unexpected content type: multipart/form-data"). We apply
  the same rewrite here. TODO(orca): extend the toolkit normalizer to walk
  components/requestBodies so this local prep can be retired.
"""
import json
import sys


def _coerce_binary_to_string(schema):
    """Recursively drop `format: binary` so a body field becomes a plain string
    rather than a binary blob (which progenitor renders as `Into<reqwest::Body>`
    — a type the delegated-http reqwest shim does not provide)."""
    if isinstance(schema, dict):
        if schema.get("format") == "binary":
            schema.pop("format", None)
            schema["type"] = "string"
        for v in schema.values():
            _coerce_binary_to_string(v)
    elif isinstance(schema, list):
        for v in schema:
            _coerce_binary_to_string(v)


def multipart_to_json(rb):
    """Convert a multipart/form-data request body to application/json, coercing
    binary fields to strings. Keeps the field set (API fidelity) while giving
    progenitor a normal typed body — no octet-stream, no `Into<Body>` generic.

    Why not the toolkit: the orca normalizer rewrites paths-level multipart to
    application/octet-stream, which under delegated-http generates
    `B: Into<::plugin_toolkit::reqwest::Body>` — and that shim exposes no `Body`.
    Converting to json here (before the toolkit runs) sidesteps it for BOTH the
    reusable component bodies AND the paths-level ones. TODO(orca): have the
    normalizer target application/json (binary→string) instead of octet-stream
    for the delegated-http profile.
    """
    content = rb.get("content", {}) if isinstance(rb, dict) else {}
    mp_key = next((c for c in content if "multipart" in c), None)
    if mp_key is None:
        return False
    media = content.pop(mp_key)
    schema = media.get("schema", {"type": "object"})
    _coerce_binary_to_string(schema)
    content["application/json"] = {"schema": schema}
    return True


def rewrite_multipart(container):
    changed = 0
    for name, rb in list(container.items()):
        if isinstance(rb, dict) and multipart_to_json(rb):
            changed += 1
            print(f"  rewrote reusable requestBody {name} multipart -> application/json")
    return changed


def rewrite_paths_multipart(spec):
    changed = 0
    for path, ops in spec["paths"].items():
        for m, op in ops.items():
            if not isinstance(op, dict):
                continue
            rb = op.get("requestBody")
            if isinstance(rb, dict) and multipart_to_json(rb):
                changed += 1
                print(f"  {m.upper()} {path}: requestBody multipart -> application/json")
    return changed


def _resp_has_body(resp, comp_responses):
    if "$ref" in resp:
        resp = comp_responses.get(resp["$ref"].split("/")[-1], {})
    return bool(resp.get("content"))


def collapse_divergent_2xx(spec):
    """Progenitor asserts a single success response type per op. When an op has a
    bodied 2xx (e.g. 200) AND empty-body 2xx codes (204/201), keep the bodied one
    and drop the empty ones. The orca toolkit normalizer's
    `merge_success_response_schemas` is meant to fuse these into a oneOf but does
    not give empty-body 2xx a null variant, so progenitor still sees >1 type.
    TODO(orca): fix the normalizer to emit the null variant; then retire this.
    """
    comp = spec.get("components", {}).get("responses", {})
    changed = 0
    for path, ops in spec["paths"].items():
        for m, op in ops.items():
            if not isinstance(op, dict):
                continue
            resps = op.get("responses", {})
            twoxx = [c for c in resps if str(c).startswith("2")]
            if len(twoxx) <= 1:
                continue
            bodied = [c for c in twoxx if _resp_has_body(resps[c], comp)]
            empty = [c for c in twoxx if c not in bodied]
            # Only act when there's exactly one bodied 2xx + some empty ones.
            if len(bodied) == 1 and empty:
                for c in empty:
                    del resps[c]
                    changed += 1
                print(f"  {m.upper()} {path}: kept {bodied[0]}, dropped empty 2xx {empty}")
            elif len(bodied) == 0 and len(twoxx) > 1:
                # all empty: keep the first, drop the rest
                for c in twoxx[1:]:
                    del resps[c]
                    changed += 1
    return changed


def strip_typed_error_responses(spec):
    """Progenitor asserts a single response type per bucket (success = 2xx/default;
    error = 4xx/5xx/default). Gitea attaches divergent error schemas via
    response-level `$ref`s (e.g. "404": {"$ref": ".../notFound"}). The orca
    toolkit normalizer's `merge_bucket` returns None for `ReferenceOr::Reference`
    (get_success_response, normalize.rs:455) so it never resolves/unifies $ref'd
    responses — progenitor then sees >1 error type and panics.

    We drop all typed 4xx/5xx/default error responses. The generated client still
    surfaces every operation and its success type; non-2xx just map to
    `Error::UnexpectedResponse` instead of a typed error enum — no API surface
    (no method) is lost. TODO(orca): teach the normalizer to resolve response
    $refs and unify each bucket, then retire this.
    """
    changed = 0
    for path, ops in spec["paths"].items():
        for m, op in ops.items():
            if not isinstance(op, dict):
                continue
            resps = op.get("responses", {})
            drop = [
                c
                for c in list(resps)
                if c == "default" or (str(c)[:1] in ("4", "5"))
            ]
            for c in drop:
                del resps[c]
                changed += 1
    return changed


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "specs/gitea.openapi.json"
    spec = json.load(open(path))
    changed = 0
    rbs = spec.get("components", {}).get("requestBodies", {})
    changed += rewrite_multipart(rbs)
    changed += rewrite_paths_multipart(spec)
    changed += collapse_divergent_2xx(spec)
    changed += strip_typed_error_responses(spec)
    if changed:
        json.dump(spec, open(path, "w"), indent=1)
        print(f"prep_spec: rewrote {changed} reusable multipart body(ies) in {path}")
    else:
        print("prep_spec: nothing to rewrite")


if __name__ == "__main__":
    main()
