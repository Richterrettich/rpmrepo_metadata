// Copyright (c) 2022 Daniel Alley
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::io::BufReader;
use std::path::Path;

use crate::filelist::FilelistsXmlReader;
use crate::metadata::{METADATA_FILELISTS, METADATA_OTHER, METADATA_PRIMARY};
use crate::other::OtherXmlReader;
use crate::primary::PrimaryXmlReader;
use crate::{utils, RepomdData};
use crate::{FilelistsXml, MetadataError, OtherXml, Package, PrimaryXml};
use std::cmp::Ord;

#[cfg(feature = "read_rpm")]
pub mod rpm_parsing {
    use std::cmp::Ordering;
    use std::collections::BTreeSet;
    use std::time::SystemTime;
    use std::{collections::HashSet, fs::File};

    use crate::{Changelog, ChecksumType, PackageFile, Requirement, EVR};

    use super::*;
    use rpm::{self, Dependency, FileMode};

    impl TryFrom<rpm::Dependency> for Requirement {
        type Error = MetadataError;

        fn try_from(d: rpm::Dependency) -> Result<Self, Self::Error> {
            let flags = if d.flags.contains(rpm::DependencyFlags::GE) {
                Some("GE".to_owned())
            } else if d.flags.contains(rpm::DependencyFlags::LE) {
                Some("LE".to_owned())
            } else if d.flags.contains(rpm::DependencyFlags::EQUAL) {
                Some("EQ".to_owned())
            } else if d.flags.contains(rpm::DependencyFlags::LESS) {
                Some("LT".to_owned())
            } else if d.flags.contains(rpm::DependencyFlags::GREATER) {
                Some("GT".to_owned())
            } else {
                None
            };

            /*
            ogriginal source: https://github.com/rpm-software-management/createrepo_c/blob/70e92f6a802059f1f8d003299cea925e838745b1/src/parsehdr.c#L425
            // Calculate pre value
                    if (num_flags & (RPMSENSE_PREREQ |
                                     RPMSENSE_SCRIPT_PRE |
                                     RPMSENSE_POSTTRANS |
                                     RPMSENSE_PRETRANS |
                                     RPMSENSE_SCRIPT_POST))
                    {
                        pre = 1;
                    }
             */
            let pre = d.flags
                & (rpm::DependencyFlags::SCRIPT_PRE
                    | rpm::DependencyFlags::PREREQ
                    | rpm::DependencyFlags::POSTTRANS
                    | rpm::DependencyFlags::SCRIPT_POST);

            let evr = EVR::parse(&d.version);

            let epoch = if evr.epoch().is_empty() {
                if d.version.is_empty() {
                    None
                } else {
                    Some("0".to_string())
                }
            } else {
                Some(evr.epoch.to_string())
            };
            let version = if evr.version().is_empty() && d.version.is_empty() {
                None
            } else {
                Some(evr.version.to_string())
            };
            let release = if evr.release().is_empty() {
                None
            } else {
                Some(evr.release.to_string())
            };

            Ok(Requirement {
                name: d.name,
                flags,
                epoch,
                version,
                release,
                preinstall: !pre.is_empty(),
            })
        }
    }

    impl From<rpm::ChangelogEntry> for Changelog {
        fn from(value: rpm::ChangelogEntry) -> Self {
            Changelog {
                author: value.name,
                timestamp: value.timestamp,
                description: value.description,
            }
        }
    }

    impl From<rpm::FileEntry> for PackageFile {
        fn from(value: rpm::FileEntry) -> Self {
            // first check if it is a dir, then if it is ghost, everything else is file
            /*
            original source:
            https://github.com/rpm-software-management/createrepo_c/blob/70e92f6a802059f1f8d003299cea925e838745b1/src/parsehdr.c#L313
            if (S_ISDIR(rpmtdGetNumber(filemodes))) {
                // Directory
                packagefile->type = cr_safe_string_chunk_insert(pkg->chunk, "dir");
            } else if (rpmtdGetNumber(fileflags) & RPMFILE_GHOST) {
                // Ghost
                packagefile->type = cr_safe_string_chunk_insert(pkg->chunk, "ghost");
            } else {
                // Regular file
                packagefile->type = cr_safe_string_chunk_insert(pkg->chunk, "");
            }
            */

            let ft = if let FileMode::Dir { .. } = value.mode {
                crate::FileType::Dir
            } else if value.flags.contains(rpm::FileFlags::GHOST) {
                crate::FileType::Ghost
            } else {
                crate::FileType::File
            };
            let path = value
                .path
                .into_os_string()
                .into_string()
                .expect("failed to convert PathBuf to String");
            PackageFile { filetype: ft, path }
        }
    }

    // todo: restrict # of changelogs
    // todo: location_href, location_base
    // todo: checksum type
    pub fn load_rpm_package<A: AsRef<Path>>(path: A) -> Result<Package, MetadataError> {
        let file = File::open(&path)?;
        let file_metadata = file.metadata()?;

        let pkg = rpm::PackageMetadata::parse(&mut BufReader::new(&file))?;

        let mut pkg_metadata = Package::default();

        pkg_metadata.set_name(pkg.get_name()?);

        let arch = if pkg.is_source_package() {
            "src"
        } else {
            pkg.get_arch()?
        };

        pkg_metadata.set_arch(arch);
        pkg_metadata.set_epoch(pkg.get_epoch().unwrap_or(0));
        pkg_metadata.set_version(pkg.get_version()?);
        pkg_metadata.set_release(pkg.get_release()?);

        pkg_metadata.summary = pkg.get_summary().ok().map(From::from);
        pkg_metadata.description = pkg.get_description().ok().map(From::from);
        pkg_metadata.packager = pkg.get_packager().ok().map(From::from);
        pkg_metadata.url = pkg.get_url().ok().map(From::from);
        pkg_metadata.description = pkg.get_description().ok().map(From::from);
        pkg_metadata.set_time_build(pkg.get_build_time().unwrap_or_default());
        pkg_metadata.set_rpm_license(pkg.get_license()?);
        pkg_metadata.rpm_vendor = pkg.get_vendor().ok().map(From::from);
        pkg_metadata.rpm_group = pkg.get_group().ok().map(From::from);
        pkg_metadata.rpm_buildhost = pkg.get_build_host().ok().map(From::from);
        pkg_metadata.rpm_sourcerpm = pkg.get_source_rpm().ok().map(From::from);

        let archive_size = pkg
            .signature
            .get_entry_data_as_u64(rpm::IndexSignatureTag::RPMSIGTAG_LONGARCHIVESIZE)
            .unwrap_or_else(|_| {
                pkg.signature
                    .get_entry_data_as_u32(rpm::IndexSignatureTag::RPMSIGTAG_PAYLOADSIZE)
                    .unwrap_or(0) as u64
            });
        pkg_metadata.set_size_archive(archive_size);
        pkg_metadata.set_size_installed(pkg.get_installed_size()?);

        fn convert_deps(
            requirements: Vec<rpm::Dependency>,
            mut callback: impl FnMut(Dependency) -> Result<Option<Requirement>, MetadataError>,
        ) -> Result<Vec<Requirement>, MetadataError> {
            let mut out = HashSet::new();
            for r in requirements.into_iter() {
                let requirement = callback(r)?;
                if let Some(req) = requirement {
                    out.insert(req);
                }
            }
            let mut out = out.into_iter().collect::<Vec<Requirement>>();
            out.sort_by(|a, b| (&a.name).cmp(&b.name));
            Ok(out)
        }

        let mut libc_requirement: Option<Requirement> = None;
        let mut current_libc_version = LibcVersion::default();
        fn remove_pre_flag(dep: Dependency) -> Result<Option<Requirement>, MetadataError> {
            let mut result: Requirement = dep.try_into()?;
            result.preinstall = false;
            Ok(Some(result))
        }
        pkg_metadata.set_provides(convert_deps(pkg.get_provides()?, remove_pre_flag)?);
        let mut requires = convert_deps(pkg.get_requires()?, |dep: Dependency| {
            if dep.name.starts_with("rpmlib(") {
                return Ok(None);
            }
            if dep.name.starts_with("libc.so") {
                if let Some(version) = parse_glibc_req_version(&dep.name[..]) {
                    if version < current_libc_version {
                        return Ok(None);
                    }
                    current_libc_version = version;
                    libc_requirement = Some(dep.try_into()?);
                }
                return Ok(None);
            }
            let req = dep.try_into()?;
            // deduplicate the provides values from requires
            if pkg_metadata.provides().contains(&req) {
                return Ok(None);
            }
            Ok(Some(req))
        })?;
        // insert glibc requirement last since we have filtered out the redundant entries
        if let Some(req) = libc_requirement {
            requires.push(req);
        }

        pkg_metadata.set_requires(requires);
        pkg_metadata.set_conflicts(convert_deps(pkg.get_conflicts()?, remove_pre_flag)?);
        pkg_metadata.set_obsoletes(convert_deps(pkg.get_obsoletes()?, remove_pre_flag)?);
        pkg_metadata.set_suggests(convert_deps(pkg.get_suggests()?, remove_pre_flag)?);
        pkg_metadata.set_enhances(convert_deps(pkg.get_enhances()?, remove_pre_flag)?);
        pkg_metadata.set_recommends(convert_deps(pkg.get_recommends()?, remove_pre_flag)?);
        pkg_metadata.set_supplements(convert_deps(pkg.get_supplements()?, remove_pre_flag)?);

        // todo: restrict number
        let mut changelogs: Vec<Changelog> = Vec::new();
        for f in pkg.get_changelog_entries()?.into_iter() {
            changelogs.push(f.into())
        }
        changelogs.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        pkg_metadata.set_changelogs(changelogs);

        // todo: filter files
        let mut files: Vec<PackageFile> = Vec::new();
        for f in pkg.get_file_entries()?.into_iter() {
            files.push(f.into())
        }
        pkg_metadata.set_files(files);

        pkg_metadata.set_checksum(utils::checksum_file(path.as_ref(), ChecksumType::Sha256)?);
        pkg_metadata.set_location_href(path.as_ref().to_string_lossy());

        let file_size = file_metadata.len();
        let unix_timestamp = file_metadata
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        pkg_metadata.set_size_package(file_size);
        pkg_metadata.set_time_file(unix_timestamp);

        let offsets = pkg.get_package_segment_offsets();
        pkg_metadata.set_rpm_header_range(offsets.header, offsets.payload);

        Ok(pkg_metadata)
    }

    fn parse_glibc_req_version(input: &str) -> Option<LibcVersion> {
        if let Some(first) = input.split(")").next() {
            let raw_version = first.split("(").skip(1).next();
            if raw_version.is_none() {
                return None;
            }
            if let Some((_, version_str)) = raw_version.unwrap().split_once("_") {
                let mut parts = version_str.split(".");
                return Some(LibcVersion {
                    major: parts
                        .next()
                        .map(|item| item.parse().unwrap_or_default())
                        .unwrap_or_default(),
                    minor: parts
                        .next()
                        .map(|item| item.parse().unwrap_or_default())
                        .unwrap_or_default(),
                    patch: parts
                        .next()
                        .map(|item| item.parse().unwrap_or_default())
                        .unwrap_or_default(),
                });
            } else {
                return None;
            }
        }
        None
    }
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Default)]
    struct LibcVersion {
        major: u32,
        minor: u32,
        patch: u32,
    }

    impl LibcVersion {
        fn new(major: u32, minor: u32, patch: u32) -> Self {
            Self {
                major,
                minor,
                patch,
            }
        }
    }

    impl std::cmp::Ord for LibcVersion {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            if self.major == other.major && self.minor == other.minor && self.patch == other.patch {
                return Ordering::Equal;
            }
            if self.major > other.major
                || (self.major == other.major && self.minor > other.minor)
                || (self.major == other.major
                    && self.minor == other.minor
                    && self.patch > other.patch)
            {
                return Ordering::Greater;
            }
            return Ordering::Less;
        }
    }

    #[cfg(test)]
    mod tests {
        use std::cmp::Ordering;

        use super::{parse_glibc_req_version, LibcVersion};

        #[test]
        fn test_parse_libc_version() {
            for (raw, expected) in [
                ("libc.so.6(GLIBC_2.38)(64bit)", LibcVersion::new(2, 38, 0)),
                ("libc.so.6()(64bit)", LibcVersion::default()),
            ] {
                let actual = parse_glibc_req_version(raw).unwrap_or_default();
                assert_eq!(expected, actual)
            }
        }

        #[test]
        fn test_version_compare() {
            for (a, b, expected) in [
                (
                    LibcVersion::new(2, 0, 0),
                    LibcVersion::new(1, 123123123, 123123123),
                    Ordering::Greater,
                ),
                (
                    LibcVersion::new(1, 123, 0),
                    LibcVersion::new(1, 0, 0),
                    Ordering::Greater,
                ),
                (
                    LibcVersion::new(1, 0, 123),
                    LibcVersion::new(1, 0, 0),
                    Ordering::Greater,
                ),
                (
                    LibcVersion::new(1, 0, 0),
                    LibcVersion::new(1, 0, 0),
                    Ordering::Equal,
                ),
                (
                    LibcVersion::new(1, 123123123, 123123123),
                    LibcVersion::new(2, 0, 0),
                    Ordering::Less,
                ),
                (
                    LibcVersion::new(1, 0, 0),
                    LibcVersion::new(1, 123, 0),
                    Ordering::Less,
                ),
                (
                    LibcVersion::new(1, 0, 0),
                    LibcVersion::new(1, 0, 123),
                    Ordering::Less,
                ),
            ] {
                let actual = a.cmp(&b);
                assert_eq!(expected, actual)
            }
        }
    }
}

pub struct PackageIterator {
    primary_xml: PrimaryXmlReader<BufReader<Box<dyn std::io::Read + Send>>>,
    filelists_xml: FilelistsXmlReader<BufReader<Box<dyn std::io::Read + Send>>>,
    other_xml: OtherXmlReader<BufReader<Box<dyn std::io::Read + Send>>>,

    num_packages: usize,
    num_remaining: usize,
    in_progress_package: Option<Package>,
}

impl PackageIterator {
    pub fn from_repodata(base: &Path, repomd: &RepomdData) -> Result<Self, MetadataError> {
        let primary_path = base.join(&repomd.get_record(METADATA_PRIMARY).unwrap().location_href);
        let filelists_path =
            base.join(&repomd.get_record(METADATA_FILELISTS).unwrap().location_href);
        let other_path = base.join(&repomd.get_record(METADATA_OTHER).unwrap().location_href);
        Self::from_files(&primary_path, &filelists_path, &other_path)
    }

    pub fn from_files(
        primary_path: &Path,
        filelists_path: &Path,
        other_path: &Path,
    ) -> Result<Self, MetadataError> {
        let primary_xml = PrimaryXml::new_reader(utils::xml_reader_from_file(primary_path)?);
        let filelists_xml = FilelistsXml::new_reader(utils::xml_reader_from_file(filelists_path)?);
        let other_xml = OtherXml::new_reader(utils::xml_reader_from_file(other_path)?);

        Self::from_readers(primary_xml, filelists_xml, other_xml)
    }

    pub fn from_readers(
        primary_xml: PrimaryXmlReader<BufReader<Box<dyn std::io::Read + Send>>>,
        filelists_xml: FilelistsXmlReader<BufReader<Box<dyn std::io::Read + Send>>>,
        other_xml: OtherXmlReader<BufReader<Box<dyn std::io::Read + Send>>>,
    ) -> Result<Self, MetadataError> {
        let mut parser = Self {
            primary_xml,
            filelists_xml,
            other_xml,
            num_packages: 0,
            num_remaining: 0,
            in_progress_package: None,
        };
        parser.parse_headers()?;

        Ok(parser)
    }

    fn parse_headers(&mut self) -> Result<(), MetadataError> {
        let primary_pkg_count = self.primary_xml.read_header()?;
        let filelists_pkg_count = self.filelists_xml.read_header()?;
        let other_pkg_count = self.other_xml.read_header()?;

        if primary_pkg_count != filelists_pkg_count || primary_pkg_count != other_pkg_count {
            return Err(MetadataError::InconsistentMetadataError(
                "Metadata package counts don't match".to_owned(),
            ));
        }

        assert_eq!(primary_pkg_count, filelists_pkg_count);
        assert_eq!(primary_pkg_count, other_pkg_count);
        self.num_packages = primary_pkg_count;
        self.num_remaining = self.num_packages;

        Ok(())
    }

    pub fn parse_package(&mut self) -> Result<Option<Package>, MetadataError> {
        self.primary_xml
            .read_package(&mut self.in_progress_package)?;
        self.filelists_xml
            .read_package(&mut self.in_progress_package)?;
        self.other_xml.read_package(&mut self.in_progress_package)?;

        let package = self.in_progress_package.take();

        // TODO: re-enable this with actual error handling instead of panics - RHEL6 for example will fail
        // because the header lies about the number of packages
        if let Some(_) = package {
            self.num_remaining -= 1;
            // self.num_remaining = self
            //     .num_remaining
            //     .checked_sub(1)
            //     .expect("More packages parsed than declared in the metadata header.");
        } else {
            // assert!(
            //     self.num_remaining == 0,
            //     "Less packages parsed than declared in metadata header."
            // );
        }

        Ok(package)
    }

    pub fn remaining_packages(&self) -> usize {
        self.num_remaining
    }

    pub fn total_packages(&self) -> usize {
        self.num_packages
    }
}

impl Iterator for PackageIterator {
    type Item = Result<Package, MetadataError>;
    fn next(&mut self) -> Option<Self::Item> {
        self.parse_package().transpose()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining_packages()))
    }
}
