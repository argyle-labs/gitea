//! The `gitea dump` invocation and the checks a finished archive must pass
//! before it counts as a good backup. Pure: the substrate exec that runs these
//! argvs is not wired yet (see [`crate::backup`]).

use plugin_toolkit::prelude::*;

/// Archive format passed to `gitea dump --type`. Always explicit: Gitea's
/// default is zip, so a name or validator that assumes otherwise is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub enum DumpFormat {
    Zip,
    #[default]
    #[serde(rename = "tar.zst")]
    TarZst,
}

impl DumpFormat {
    pub fn as_type(self) -> &'static str {
        match self {
            DumpFormat::Zip => "zip",
            DumpFormat::TarZst => "tar.zst",
        }
    }
}

/// Where one dump is written. `tempdir` must sit on the same off-rootfs volume
/// as `dir`: `gitea dump` assembles the archive there first, and a rootfs
/// tempdir fills the guest disk even when the final target is elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DumpTarget {
    pub dir: String,
    pub tempdir: String,
    pub format: DumpFormat,
}

impl DumpTarget {
    /// Archive path for a dump taken at `stamp` (a compact UTC timestamp).
    pub fn archive(&self, stamp: &str) -> String {
        format!(
            "{}/gitea-dump-{stamp}.{}",
            self.dir.trim_end_matches('/'),
            self.format.as_type()
        )
    }

    /// `gitea dump` argv. Logs are skipped: they are not needed to restore and
    /// grow without bound.
    pub fn dump_argv(&self, archive: &str) -> Vec<String> {
        [
            "gitea",
            "dump",
            "--type",
            self.format.as_type(),
            "--file",
            archive,
            "--tempdir",
            &self.tempdir,
            "--skip-log",
        ]
        .map(String::from)
        .to_vec()
    }

    /// Commands that each exit 0 only for an intact archive of this format.
    pub fn verify_argvs(&self, archive: &str) -> Vec<Vec<String>> {
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        match self.format {
            DumpFormat::Zip => vec![argv(&["unzip", "-tqq", archive])],
            DumpFormat::TarZst => vec![
                argv(&["zstd", "-tq", archive]),
                argv(&["tar", "--zstd", "-tf", archive]),
            ],
        }
    }

    /// Refuse a tempdir outside the target dir: see the type docs.
    pub fn validate(&self) -> Result<()> {
        for (what, p) in [("dir", &self.dir), ("tempdir", &self.tempdir)] {
            if !p.starts_with('/') {
                bail!("{what} `{p}` is not an absolute path");
            }
            // The prefix check below is lexical; `..` would escape it.
            if p.split('/').any(|c| c == "..") {
                bail!("{what} `{p}` contains a `..` component");
            }
        }
        let dir = self.dir.trim_end_matches('/');
        if self.tempdir.trim_end_matches('/') != dir
            && !self.tempdir.starts_with(&format!("{dir}/"))
        {
            bail!(
                "tempdir `{}` is not under dir `{}`; the dump would be assembled on another volume",
                self.tempdir,
                self.dir
            );
        }
        Ok(())
    }
}

/// Reject a dump that is empty or more than `max_shrink_pct` percent smaller
/// than the last good one: the signature of a dump truncated by a full disk.
pub fn check_size(bytes: u64, last_good: Option<u64>, max_shrink_pct: u8) -> Result<()> {
    if bytes == 0 {
        bail!("dump is empty");
    }
    if let Some(prev) = last_good {
        let floor = prev - prev * u64::from(max_shrink_pct.min(100)) / 100;
        if bytes < floor {
            bail!(
                "dump is {bytes} bytes, under {floor} ({max_shrink_pct}% below the last good dump of {prev} bytes); likely truncated"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(format: DumpFormat) -> DumpTarget {
        DumpTarget {
            dir: "/mnt/backup/gitea/".into(),
            tempdir: "/mnt/backup/gitea/tmp".into(),
            format,
        }
    }

    #[test]
    fn archive_name_matches_the_format_passed_to_dump() {
        for f in [DumpFormat::Zip, DumpFormat::TarZst] {
            let t = target(f);
            let a = t.archive("20261013T000000Z");
            assert!(a.ends_with(&format!(".{}", f.as_type())), "{a}");
            let argv = t.dump_argv(&a);
            let ty = argv.iter().position(|s| s == "--type").unwrap();
            assert_eq!(argv[ty + 1], f.as_type());
            let tmp = argv.iter().position(|s| s == "--tempdir").unwrap();
            assert_eq!(argv[tmp + 1], "/mnt/backup/gitea/tmp");
        }
        assert_eq!(
            target(DumpFormat::TarZst).archive("s"),
            "/mnt/backup/gitea/gitea-dump-s.tar.zst"
        );
    }

    #[test]
    fn verifier_follows_the_format() {
        assert_eq!(target(DumpFormat::Zip).verify_argvs("a")[0][0], "unzip");
        let tz = target(DumpFormat::TarZst).verify_argvs("a");
        assert_eq!(
            tz.iter().map(|a| a[0].as_str()).collect::<Vec<_>>(),
            ["zstd", "tar"]
        );
    }

    #[test]
    fn tempdir_must_share_the_target_volume() {
        target(DumpFormat::TarZst).validate().unwrap();
        let mut t = target(DumpFormat::TarZst);
        t.tempdir = "/tmp".into();
        assert!(
            t.validate()
                .unwrap_err()
                .to_string()
                .contains("not under dir")
        );
        t.tempdir = "/mnt/backup/gitea-other".into();
        assert!(t.validate().is_err());
        t.tempdir = "relative".into();
        assert!(t.validate().unwrap_err().to_string().contains("absolute"));
    }

    #[test]
    fn dotdot_components_are_rejected() {
        let mut t = target(DumpFormat::TarZst);
        t.tempdir = "/mnt/backup/gitea/../../tmp".into();
        assert!(t.validate().unwrap_err().to_string().contains(".."));
        let mut t = target(DumpFormat::TarZst);
        t.dir = "/mnt/../backup/gitea".into();
        assert!(t.validate().is_err());
        t = target(DumpFormat::TarZst);
        t.tempdir = "/mnt/backup/gitea/tmp..x".into();
        t.validate().unwrap();
    }

    #[test]
    fn size_check_catches_empty_and_truncated_dumps() {
        assert!(check_size(0, None, 50).is_err());
        check_size(10, None, 50).unwrap();
        check_size(60, Some(100), 50).unwrap();
        check_size(50, Some(100), 50).unwrap();
        assert!(
            check_size(49, Some(100), 50)
                .unwrap_err()
                .to_string()
                .contains("truncated")
        );
    }
}
