//! Execute a step list on this host, recording what each step did.

use std::path::Path;

use plugin_toolkit::prelude::*;

use super::api;
use super::host::LocalHost;
use super::layout::managed_root;
use super::plan::Step;
use super::release;
use crate::Config;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StepOutcome {
    pub target: String,
    pub action: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

pub struct Executor<'a> {
    pub host: &'a LocalHost,
    /// Needed only by register/deregister steps.
    pub gitea: Option<&'a Config>,
    pub release_api: &'a str,
    pub release_target: &'a str,
}

/// Write `contents` beside `path` and rename over it, so a reader (launchd,
/// a running runner) never sees a half-written file.
fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("{} has no file name", path.display()))?;
    let tmp = path.with_file_name(format!(".{}.orca-new", file_name.to_string_lossy()));
    std::fs::write(&tmp, contents).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename onto {}", path.display()))?;
    Ok(())
}

fn scrub(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        text.to_string()
    } else {
        text.replace(secret, "<redacted>")
    }
}

impl Executor<'_> {
    fn gitea(&self) -> Result<&Config> {
        self.gitea
            .ok_or_else(|| anyhow!("this step needs a Gitea endpoint (pass `endpoint`)"))
    }

    async fn step(&self, step: &Step) -> Result<Option<String>> {
        match step {
            Step::CreateDir(p) => {
                std::fs::create_dir_all(p).with_context(|| format!("create {}", p.display()))?;
                Ok(None)
            }
            Step::InstallBinary { version, dest } => {
                let bin = release::resolve(self.release_api, version, self.release_target)?;
                let bytes = release::download(&bin)?;
                write_atomic(dest, &bytes, 0o755)?;
                Ok(Some(format!(
                    "installed {} ({}, sha256 {} verified)",
                    bin.version, bin.asset, bin.sha256
                )))
            }
            Step::WriteFile {
                path,
                contents,
                mode,
                ..
            } => {
                write_atomic(path, contents.as_bytes(), *mode)?;
                Ok(None)
            }
            Step::Register {
                binary,
                config,
                dir,
                name,
                labels,
                instance_url,
                scope,
            } => {
                let token = api::registration_token(self.gitea()?, scope).await?;
                let argv: Vec<String> = [
                    binary.display().to_string(),
                    "register".into(),
                    "--no-interactive".into(),
                    "--instance".into(),
                    instance_url.clone(),
                    "--token".into(),
                    token.clone(),
                    "--name".into(),
                    name.clone(),
                    "--labels".into(),
                    labels.join(","),
                    "--config".into(),
                    config.display().to_string(),
                ]
                .into();
                let out = self.host.run(&argv, Some(dir)).await?;
                if !out.ok {
                    bail!(
                        "act_runner register exited {:?}: {}",
                        out.code,
                        scrub(&format!("{} {}", out.stderr, out.stdout), &token).trim()
                    );
                }
                Ok(Some(format!("registered {name} ({})", scope.label())))
            }
            Step::Run {
                argv,
                tolerate_failure,
            } => {
                let out = self.host.run(argv, None).await?;
                if out.ok {
                    return Ok(None);
                }
                let why = format!(
                    "exit {:?}: {}",
                    out.code,
                    if out.stderr.is_empty() {
                        &out.stdout
                    } else {
                        &out.stderr
                    }
                );
                if *tolerate_failure {
                    Ok(Some(format!("tolerated {why}")))
                } else {
                    bail!("{why}")
                }
            }
            Step::Deregister { runner_id, scope } => {
                let existed = api::deregister(self.gitea()?, scope, *runner_id).await?;
                Ok((!existed).then(|| "already absent in Gitea".to_string()))
            }
            Step::Remove { path, recursive } => {
                let result = if *recursive {
                    // Recursive removal is confined to the managed root so a bad
                    // layout can never take out anything else on the host.
                    let root = managed_root(self.host.init, &self.host.home);
                    if !path.starts_with(&root) || path == &root {
                        bail!(
                            "refusing to remove {} (outside {})",
                            path.display(),
                            root.display()
                        );
                    }
                    std::fs::remove_dir_all(path)
                } else {
                    std::fs::remove_file(path)
                };
                match result {
                    Ok(()) => Ok(None),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        Ok(Some("already absent".to_string()))
                    }
                    Err(e) => Err(anyhow!("remove {}: {e}", path.display())),
                }
            }
        }
    }

    /// Run `steps` in order, stopping at the first failure. Returns every
    /// outcome so far plus the error, if one stopped the run.
    pub async fn run(&self, steps: &[Step]) -> (Vec<StepOutcome>, Option<anyhow::Error>) {
        let mut outcomes = Vec::new();
        for step in steps {
            let change = step.to_change();
            match self.step(step).await {
                Ok(detail) => outcomes.push(StepOutcome {
                    target: change.target,
                    action: change.action,
                    ok: true,
                    detail,
                }),
                Err(e) => {
                    outcomes.push(StepOutcome {
                        target: change.target,
                        action: change.action,
                        ok: false,
                        detail: Some(format!("{e:#}")),
                    });
                    return (outcomes, Some(e));
                }
            }
        }
        (outcomes, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::layout::Init;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("gitea-exec-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn atomic_write_sets_mode_and_leaves_no_temp() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("write");
        let p = d.join("nested/unit");
        write_atomic(&p, b"x", 0o755).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"x");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(std::fs::read_dir(d.join("nested")).unwrap().count(), 1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn scrub_redacts_the_token() {
        assert_eq!(scrub("bad token abc123", "abc123"), "bad token <redacted>");
    }

    #[tokio::test]
    async fn recursive_remove_is_confined_to_the_managed_root() {
        let home = scratch("home");
        let host = LocalHost {
            init: Init::Launchd,
            home: home.clone(),
            uid: 501,
        };
        let exec = Executor {
            host: &host,
            gitea: None,
            release_api: "",
            release_target: "darwin-arm64",
        };
        let outside = home.join("precious");
        std::fs::create_dir_all(&outside).unwrap();
        let (out, err) = exec
            .run(&[Step::Remove {
                path: outside.clone(),
                recursive: true,
            }])
            .await;
        assert!(err.is_some() && !out[0].ok);
        assert!(outside.exists());

        let inside = managed_root(Init::Launchd, &home).join("r1");
        std::fs::create_dir_all(inside.join("work")).unwrap();
        let (out, err) = exec
            .run(&[
                Step::Remove {
                    path: inside.clone(),
                    recursive: true,
                },
                Step::Remove {
                    path: inside.clone(),
                    recursive: true,
                },
            ])
            .await;
        assert!(err.is_none(), "{err:?}");
        assert!(!inside.exists());
        assert_eq!(out[1].detail.as_deref(), Some("already absent"));
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[tokio::test]
    async fn a_failed_step_stops_the_run_and_tolerated_ones_do_not() {
        let home = scratch("run");
        let host = LocalHost {
            init: Init::Launchd,
            home: home.clone(),
            uid: 501,
        };
        let exec = Executor {
            host: &host,
            gitea: None,
            release_api: "",
            release_target: "",
        };
        let steps = vec![
            Step::Run {
                argv: vec!["false".into()],
                tolerate_failure: true,
            },
            Step::Run {
                argv: vec!["false".into()],
                tolerate_failure: false,
            },
            Step::Run {
                argv: vec!["true".into()],
                tolerate_failure: false,
            },
        ];
        let (out, err) = exec.run(&steps).await;
        assert_eq!(out.len(), 2);
        assert!(out[0].ok && out[0].detail.as_deref().unwrap().starts_with("tolerated"));
        assert!(!out[1].ok);
        assert!(err.is_some());
        std::fs::remove_dir_all(&home).unwrap();
    }
}
