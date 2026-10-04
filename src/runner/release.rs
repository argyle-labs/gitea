//! Where runner binaries come from and how they are verified.
//!
//! Upstream publishes no signatures, only checksums served from the same place
//! as the binaries, which protect against corruption but not against a
//! compromised or substituted source. So the trust root is a table of sha256s
//! pinned in this plugin: a version/platform not in [`PINNED`] cannot be
//! installed. Each pin was cross-checked against two independent upstream
//! publications (`checksums.txt` on gitea.com and the per-asset `.sha256` on
//! dl.gitea.com).
//!
//! The source is operator config, not a call argument: [`SOURCE_ENV`] on the
//! orca daemon (inherited by the plugin process) may point at a mirror, which
//! must be https and whose host must be gitea.com or listed in
//! [`ALLOWED_HOSTS_ENV`].

use plugin_toolkit::client::{Client, Request};
use plugin_toolkit::prelude::*;

/// Upstream release repository.
pub const DEFAULT_SOURCE: &str = "https://gitea.com/gitea/runner";
/// Operator override: base URL of a Gitea repository mirroring the releases.
pub const SOURCE_ENV: &str = "ORCA_GITEA_RUNNER_RELEASE_SOURCE";
/// Operator allowlist: comma-separated hosts a mirror may live on.
pub const ALLOWED_HOSTS_ENV: &str = "ORCA_GITEA_RUNNER_RELEASE_HOSTS";
const BUILTIN_ALLOWED_HOSTS: &[&str] = &["gitea.com"];

const DOWNLOAD_TIMEOUT_MS: u64 = 300_000;

/// `(version, release target, asset name, sha256)`.
pub const PINNED: &[(&str, &str, &str, &str)] = &[
    (
        "4.1.0",
        "darwin-arm64",
        "gitea-runner-4.1.0-darwin-arm64",
        "3f1191ea1da7e64f93ff02295db7884b454eef69ceaa87eaf58ca2f583b75c81",
    ),
    (
        "4.1.0",
        "darwin-amd64",
        "gitea-runner-4.1.0-darwin-amd64",
        "eecac821bae95e3aea2285f3076e17610419447b205e63c9925a51ca56ee9769",
    ),
    (
        "4.1.0",
        "linux-amd64",
        "gitea-runner-4.1.0-linux-amd64",
        "b781d26b0f82269e73f6fae813a84c8ba5a215ea65cd7949c2fb3db5e0ccc8cf",
    ),
    (
        "4.1.0",
        "linux-arm64",
        "gitea-runner-4.1.0-linux-arm64",
        "42c2c66e67e09fbcd74c3ab26abc038b644ceaad13e3205e59c8eb7e65a65801",
    ),
    (
        "3.1.0",
        "darwin-arm64",
        "gitea-runner-3.1.0-darwin-arm64",
        "91a19fd5481037e34fc5435f464708b3e0eba6719791fc76ec7146c01e0e7eef",
    ),
    (
        "3.1.0",
        "darwin-amd64",
        "gitea-runner-3.1.0-darwin-amd64",
        "de6664193015cf4f10355f48d9dca1c0d54a3edfeb7bcbc42fbffcd725a5b320",
    ),
    (
        "3.1.0",
        "linux-amd64",
        "gitea-runner-3.1.0-linux-amd64",
        "377842d074b331bee7a94a18dc5310636d44ec5cbadbcb1052809d34a6543ef3",
    ),
    (
        "3.1.0",
        "linux-arm64",
        "gitea-runner-3.1.0-linux-arm64",
        "9f7d3bb909feb368cbe5e46f350aba6939772d674ec2c98abfe0db92a8815fb1",
    ),
];

/// Newest pinned version; the default for install and upgrade.
pub const DEFAULT_VERSION: &str = "4.1.0";

/// Accept only `MAJOR.MINOR.PATCH` with an optional `-suffix`/`.suffix`, with or
/// without a leading `v`. Returns the version without the `v`. This is what
/// keeps `/`, `?`, `#` and friends out of the download URL.
pub fn validate_version(v: &str) -> Result<String> {
    let bare = v.strip_prefix('v').unwrap_or(v);
    let bad = || anyhow!("invalid runner version '{v}' (expected MAJOR.MINOR.PATCH)");
    let bytes = bare.as_bytes();
    let mut i = 0;
    for part in 0..3 {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return Err(bad());
        }
        if part < 2 {
            if bytes.get(i) != Some(&b'.') {
                return Err(bad());
            }
            i += 1;
        }
    }
    if i < bytes.len() {
        let suffix = &bytes[i + 1..];
        let ok = matches!(bytes[i], b'-' | b'.')
            && !suffix.is_empty()
            && suffix
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'.');
        if !ok {
            return Err(bad());
        }
    }
    Ok(bare.to_string())
}

/// Major component of a validated version.
pub fn major(version: &str) -> Option<u64> {
    version
        .trim_start_matches('v')
        .split('.')
        .next()?
        .parse()
        .ok()
}

/// A checked release source: an https Gitea repository URL on an allowed host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub base: String,
    pub host: String,
}

fn https_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split('/').next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some(authority.split(':').next().unwrap_or(authority))
}

impl Source {
    /// Validate a source URL against the allowlist.
    pub fn parse(url: &str, extra_hosts: &[String]) -> Result<Source> {
        let base = url.trim().trim_end_matches('/').to_string();
        let host = https_host(&base)
            .ok_or_else(|| anyhow!("release source '{base}' must be an https URL"))?
            .to_ascii_lowercase();
        let allowed = BUILTIN_ALLOWED_HOSTS.contains(&host.as_str())
            || extra_hosts.iter().any(|h| h.eq_ignore_ascii_case(&host));
        if !allowed {
            bail!(
                "release source host '{host}' is not allowed; add it to {ALLOWED_HOSTS_ENV} on the orca daemon"
            );
        }
        if base.contains(['?', '#']) {
            bail!("release source '{base}' must not carry a query or fragment");
        }
        Ok(Source { base, host })
    }

    /// The operator-configured source, or upstream.
    pub fn configured() -> Result<Source> {
        let url = std::env::var(SOURCE_ENV).unwrap_or_else(|_| DEFAULT_SOURCE.to_string());
        let extra: Vec<String> = std::env::var(ALLOWED_HOSTS_ENV)
            .unwrap_or_default()
            .split(',')
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .collect();
        Source::parse(&url, &extra)
    }
}

/// A binary to install: where it comes from and the hash it must have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub version: String,
    pub asset: String,
    pub url: String,
    pub host: String,
    pub sha256: String,
}

/// Resolve `version` for `target` against `source`. Pure: no network.
pub fn artifact(source: &Source, version: &str, target: &str) -> Result<Artifact> {
    let version = validate_version(version)?;
    let (_, _, asset, sha) = PINNED
        .iter()
        .find(|(v, t, _, _)| *v == version && *t == target)
        .ok_or_else(|| {
            let known: Vec<&str> = PINNED
                .iter()
                .filter(|(_, t, _, _)| *t == target)
                .map(|(v, _, _, _)| *v)
                .collect();
            anyhow!(
                "runner {version} for {target} has no pinned checksum in this plugin; pinned: [{}]",
                known.join(", ")
            )
        })?;
    let url = format!("{}/releases/download/v{version}/{asset}", source.base);
    if https_host(&url).map(str::to_ascii_lowercase).as_deref() != Some(source.host.as_str()) {
        bail!(
            "asset URL {url} is not on the release source host {}",
            source.host
        );
    }
    Ok(Artifact {
        version,
        asset: asset.to_string(),
        url,
        host: source.host.clone(),
        sha256: sha.to_string(),
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

/// Download and verify an artifact, returning its bytes.
pub fn download(a: &Artifact) -> Result<Vec<u8>> {
    let resp = Client::new()
        .send(Request::new("GET", &a.url).timeout_ms(DOWNLOAD_TIMEOUT_MS))
        .with_context(|| format!("GET {}", a.url))?;
    if !resp.is_success() {
        bail!("GET {}: HTTP {}", a.url, resp.status);
    }
    verify(&resp.body, &a.sha256).with_context(|| format!("verify {}", a.asset))?;
    Ok(resp.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream() -> Source {
        Source::parse(DEFAULT_SOURCE, &[]).unwrap()
    }

    #[test]
    fn versions_are_strictly_shaped() {
        assert_eq!(validate_version("4.1.0").unwrap(), "4.1.0");
        assert_eq!(validate_version("v4.1.0").unwrap(), "4.1.0");
        assert_eq!(validate_version("4.1.0-rc.1").unwrap(), "4.1.0-rc.1");
        for bad in [
            "",
            "latest",
            "4.1",
            "4.1.0/../../x",
            "4.1.0?x=1",
            "4.1.0#f",
            "../4.1.0",
            "4.1.0-",
            "4.1.0-a/b",
            "4.1.0%2e",
            "a.b.c",
            "4.1.0 ",
            " 4.1.0",
            "vv4.1.0",
        ] {
            assert!(validate_version(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn major_reads_the_first_component() {
        assert_eq!(major("v3.1.0"), Some(3));
        assert_eq!(major("4.1.0"), Some(4));
    }

    #[test]
    fn sources_must_be_https_on_an_allowed_host() {
        assert_eq!(upstream().host, "gitea.com");
        assert!(Source::parse("http://gitea.com/gitea/runner", &[]).is_err());
        assert!(Source::parse("https://evil.test/gitea/runner", &[]).is_err());
        assert!(Source::parse("https://user@gitea.com/x", &[]).is_err());
        assert!(Source::parse("https://gitea.com/x?y", &[]).is_err());
        let mirror = Source::parse(
            "https://git.internal.test/mirror/runner/",
            &["git.internal.test".into()],
        )
        .unwrap();
        assert_eq!(mirror.base, "https://git.internal.test/mirror/runner");
    }

    #[test]
    fn artifacts_come_only_from_pins_on_the_source_host() {
        let a = artifact(&upstream(), "v4.1.0", "darwin-arm64").unwrap();
        assert_eq!(
            a.url,
            "https://gitea.com/gitea/runner/releases/download/v4.1.0/gitea-runner-4.1.0-darwin-arm64"
        );
        assert_eq!(a.host, "gitea.com");
        assert_eq!(
            a.sha256,
            "3f1191ea1da7e64f93ff02295db7884b454eef69ceaa87eaf58ca2f583b75c81"
        );
        let err = artifact(&upstream(), "9.9.9", "linux-amd64")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no pinned checksum"), "{err}");
        assert!(artifact(&upstream(), "4.1.0/../../evil", "linux-amd64").is_err());
    }

    #[test]
    fn every_pin_is_well_formed() {
        for (v, t, asset, sha) in PINNED {
            assert!(validate_version(v).is_ok());
            assert!(asset.ends_with(&format!("{v}-{t}")));
            assert_eq!(sha.len(), 64);
            assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
        }
        assert!(PINNED.iter().any(|(v, ..)| *v == DEFAULT_VERSION));
    }

    #[test]
    fn verify_accepts_matching_and_rejects_tampered_bytes() {
        let good = sha256_hex(b"runner");
        assert!(verify(b"runner", &good).is_ok());
        let err = verify(b"tampered", &good).unwrap_err().to_string();
        assert!(err.contains("checksum mismatch"), "{err}");
    }
}
