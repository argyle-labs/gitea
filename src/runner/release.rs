//! Resolve, download and checksum-verify a runner release binary.
//!
//! Releases are looked up through the forge's release API rather than a
//! hard-coded download URL: upstream renamed both the project (`act_runner` →
//! `runner`) and the asset prefix (`act_runner-` → `gitea-runner-`), and picking
//! the asset by its `-<os>-<arch>` suffix survives both.

use plugin_toolkit::client::{Client, Request};
use plugin_toolkit::prelude::*;

/// Upstream release API. Overridable so a fleet can mirror releases internally.
pub const DEFAULT_RELEASE_API: &str = "https://gitea.com/api/v1/repos/gitea/runner";

const DOWNLOAD_TIMEOUT_MS: u64 = 300_000;

#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseAssetJson {
    pub name: String,
    pub browser_download_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseJson {
    pub tag_name: String,
    #[serde(default)]
    pub assets: Vec<ReleaseAssetJson>,
}

/// A binary chosen from a release, with the checksum it must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBinary {
    pub version: String,
    pub asset: String,
    pub url: String,
    pub sha256: String,
}

/// Normalise a requested version to a release-API path segment.
pub fn release_path(version: &str) -> String {
    let v = version.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("latest") {
        "releases/latest".to_string()
    } else {
        format!("releases/tags/v{}", v.trim_start_matches('v'))
    }
}

/// The uncompressed binary for `target` (e.g. `darwin-arm64`). An exact
/// suffix match skips the `.xz` and `.sha256` siblings.
pub fn pick_binary<'a>(
    assets: &'a [ReleaseAssetJson],
    target: &str,
) -> Option<&'a ReleaseAssetJson> {
    let suffix = format!("-{target}");
    assets.iter().find(|a| a.name.ends_with(&suffix))
}

/// The hash for `asset` in a `sha256sum`-format file (`<hex>  <name>`), which
/// covers both `checksums.txt` and per-asset `.sha256` files.
pub fn checksum_for(text: &str, asset: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let mut cols = line.split_whitespace();
        let hash = cols.next()?;
        let name = cols.next()?.trim_start_matches('*');
        (name == asset && hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    })
}

/// Fail unless `bytes` hash to `expected`.
pub fn verify(bytes: &[u8], expected: &str) -> Result<()> {
    let got = sha256_hex(bytes);
    if !got.eq_ignore_ascii_case(expected) {
        bail!("checksum mismatch: expected sha256 {expected}, downloaded file has {got}");
    }
    Ok(())
}

fn get(url: &str, timeout_ms: u64) -> Result<Vec<u8>> {
    let resp = Client::new()
        .send(Request::new("GET", url).timeout_ms(timeout_ms))
        .with_context(|| format!("GET {url}"))?;
    if !resp.is_success() {
        bail!("GET {url}: HTTP {}", resp.status);
    }
    Ok(resp.body)
}

/// Resolve `version` for `target` against `release_api`: the binary's URL and
/// the checksum published alongside it. A release with no checksum for the
/// binary is refused — an unverifiable binary is not installed.
pub fn resolve(release_api: &str, version: &str, target: &str) -> Result<ResolvedBinary> {
    let url = format!(
        "{}/{}",
        release_api.trim_end_matches('/'),
        release_path(version)
    );
    let release: ReleaseJson = serde_json_from(&get(&url, 30_000)?)
        .with_context(|| format!("parse release JSON from {url}"))?;
    let bin = pick_binary(&release.assets, target).ok_or_else(|| {
        anyhow!(
            "release {} has no binary for {target} (assets: {})",
            release.tag_name,
            release
                .assets
                .iter()
                .map(|a| a.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    let sums = ["checksums.txt".to_string(), format!("{}.sha256", bin.name)];
    let mut sha = None;
    for sum_name in &sums {
        if let Some(asset) = release.assets.iter().find(|a| &a.name == sum_name) {
            let text =
                String::from_utf8_lossy(&get(&asset.browser_download_url, 30_000)?).into_owned();
            if let Some(h) = checksum_for(&text, &bin.name) {
                sha = Some(h);
                break;
            }
        }
    }
    let sha256 = sha.ok_or_else(|| {
        anyhow!(
            "release {} publishes no checksum for {}; refusing to install an unverified binary",
            release.tag_name,
            bin.name
        )
    })?;
    Ok(ResolvedBinary {
        version: release.tag_name.clone(),
        asset: bin.name.clone(),
        url: bin.browser_download_url.clone(),
        sha256,
    })
}

/// Download and verify a resolved binary, returning its bytes.
pub fn download(bin: &ResolvedBinary) -> Result<Vec<u8>> {
    let bytes = get(&bin.url, DOWNLOAD_TIMEOUT_MS)?;
    verify(&bytes, &bin.sha256).with_context(|| format!("verify {}", bin.asset))?;
    Ok(bytes)
}

fn serde_json_from<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(plugin_toolkit::serde_json::from_slice(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(name: &str) -> ReleaseAssetJson {
        ReleaseAssetJson {
            name: name.to_string(),
            browser_download_url: format!("https://dl.test/{name}"),
        }
    }

    #[test]
    fn release_path_normalises_versions() {
        assert_eq!(release_path("latest"), "releases/latest");
        assert_eq!(release_path(""), "releases/latest");
        assert_eq!(release_path("4.1.0"), "releases/tags/v4.1.0");
        assert_eq!(release_path("v4.1.0"), "releases/tags/v4.1.0");
    }

    #[test]
    fn picks_the_raw_binary_under_either_prefix() {
        let new = vec![
            asset("checksums.txt"),
            asset("gitea-runner-4.1.0-darwin-arm64.xz"),
            asset("gitea-runner-4.1.0-darwin-arm64.xz.sha256"),
            asset("gitea-runner-4.1.0-darwin-arm64"),
            asset("gitea-runner-4.1.0-linux-amd64"),
        ];
        assert_eq!(
            pick_binary(&new, "darwin-arm64").unwrap().name,
            "gitea-runner-4.1.0-darwin-arm64"
        );
        let old = vec![
            asset("act_runner-0.2.11-linux-amd64"),
            asset("act_runner-0.2.11-linux-amd64.sha256"),
        ];
        assert_eq!(
            pick_binary(&old, "linux-amd64").unwrap().name,
            "act_runner-0.2.11-linux-amd64"
        );
        assert!(pick_binary(&old, "darwin-arm64").is_none());
    }

    #[test]
    fn checksum_lookup_matches_the_exact_asset() {
        let sums = "\
eecac821bae95e3aea2285f3076e17610419447b205e63c9925a51ca56ee9769  gitea-runner-4.1.0-darwin-amd64
141bd96e29e5704289cf888b7ae872ffcf41d14f39b8af031e2ab2978449f769  gitea-runner-4.1.0-darwin-arm64.xz
3f1191ea1da7e64f93ff02295db7884b454eef69ceaa87eaf58ca2f583b75c81  gitea-runner-4.1.0-darwin-arm64
";
        assert_eq!(
            checksum_for(sums, "gitea-runner-4.1.0-darwin-arm64").as_deref(),
            Some("3f1191ea1da7e64f93ff02295db7884b454eef69ceaa87eaf58ca2f583b75c81")
        );
        assert_eq!(checksum_for(sums, "gitea-runner-4.1.0-linux-amd64"), None);
        assert_eq!(checksum_for("nothex  x", "x"), None);
    }

    #[test]
    fn verify_accepts_matching_and_rejects_tampered_bytes() {
        let good = sha256_hex(b"runner");
        assert!(verify(b"runner", &good).is_ok());
        let err = verify(b"tampered", &good).unwrap_err().to_string();
        assert!(err.contains("checksum mismatch"), "{err}");
    }
}
