//! Generate the typed Gitea client from the vendored OpenAPI spec.
//!
//! Refresh the vendored spec from a live instance (Gitea ships Swagger 2.0 at
//! `/swagger.v1.json`; progenitor needs OpenAPI 3.0, so convert first):
//!   curl -s https://gitea.example/swagger.v1.json > specs/gitea.swagger2.json
//!   npx -y swagger2openapi@7 specs/gitea.swagger2.json -o specs/gitea.openapi.json

fn main() {
    let specs_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));

    // Gitea returns bodies directly (no `{"data": …}` envelope like PVE), speaks
    // real JSON booleans/numbers, and its converted spec is clean OpenAPI 3.0 —
    // so no unwrapper and no lenient deserializers are needed.
    plugin_toolkit_build::openapi::generate_all_with_options(
        &specs_dir,
        "gitea",
        plugin_toolkit_build::openapi::CodegenOptions {
            unwrapper: None,
            lenient_booleans: false,
            lenient_numbers: false,
        },
    )
    .expect("gitea openapi codegen");

    // Emit the orca tool surface from the codegen'd client. Write methods
    // surface as `data_mutation = true` + `role = "admin"`; an operation can opt
    // out to `role = "read"` via `x-orca-user-callable: true` in the spec.
    plugin_toolkit_build::surface::openapi::generate(&specs_dir, &out_dir, "gitea")
        .expect("gitea surface codegen");
}
