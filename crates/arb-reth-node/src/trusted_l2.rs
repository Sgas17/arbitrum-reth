//! Node-local trusted-L2 divergence protection.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::B256;
use eyre::eyre;
use jsonrpsee::{core::client::ClientT, http_client::{HttpClient, HttpClientBuilder}, rpc_params};
use serde::{Deserialize, Serialize};

const INCIDENT_DIR: &str = "arb-trusted-l2";
const ACTIVE_INCIDENT: &str = "active.json";
const SCHEMA_VERSION: u32 = 1;
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderObservation {
    pub number: u64,
    pub hash: B256,
    pub state_root: B256,
}

#[derive(Debug, Serialize)]
struct Incident {
    schema_version: u32,
    effective_chain_id: u64,
    l2_block_number: u64,
    local_hash: B256,
    canonical_hash: B256,
    local_state_root: B256,
    canonical_state_root: B256,
    detected_at_unix_secs: u64,
}

pub struct TrustedL2Monitor {
    chain_id: u64,
    incident_path: PathBuf,
    client: HttpClient,
}

/// First local height that must be compared after observing `tip`.
///
/// A same-height header replacement is not a match merely because its number was checked before.
/// A lower tip can occur after a local rewind, so it becomes the new comparison start.
pub fn first_unchecked_height(
    last_checked: Option<HeaderObservation>,
    tip: HeaderObservation,
) -> eyre::Result<Option<u64>> {
    let Some(last) = last_checked else {
        return Ok(Some(tip.number));
    };
    if tip.number < last.number || tip.number == last.number && tip != last {
        return Ok(Some(tip.number));
    }
    if tip.number == last.number {
        return Ok(None);
    }
    last.number
        .checked_add(1)
        .map(Some)
        .ok_or_else(|| eyre!("durable L2 block number overflow"))
}

impl TrustedL2Monitor {
    pub async fn start(data_dir: &Path, rpc_url: &str, chain_id: u64) -> eyre::Result<Self> {
        let incident_path = active_incident_path(data_dir);
        refuse_active_incident(&incident_path)?;
        let client = HttpClientBuilder::default()
            .build(rpc_url)
            .map_err(|_| eyre!("invalid --canonical-l2-rpc URL"))?;
        let remote_chain_id: String = client
            .request("eth_chainId", rpc_params![])
            .await
            .map_err(|_| eyre!("trusted L2 RPC chain-id request failed"))?;
        validate_chain_id(chain_id, parse_quantity(&remote_chain_id).map_err(|_| eyre!("trusted L2 RPC returned a malformed chain id"))?)?;
        Ok(Self { chain_id, incident_path, client })
    }

    pub async fn canonical_header(&self, number: u64) -> eyre::Result<Option<HeaderObservation>> {
        let response: Option<RemoteHeader> = self
            .client
            .request("eth_getBlockByNumber", rpc_params![format!("0x{number:x}"), false])
            .await
            .map_err(|_| eyre!("trusted L2 RPC unavailable"))?;
        response
            .map(|header| header.into_observation(number))
            .transpose()
            .map_err(|_| eyre!("trusted L2 RPC returned an unavailable block"))
    }

    pub fn compare_and_record(
        &self,
        local: HeaderObservation,
        canonical: HeaderObservation,
    ) -> eyre::Result<Comparison> {
        if local.number != canonical.number {
            return Err(eyre!("cannot compare different L2 block heights"));
        }
        if local.hash == canonical.hash && local.state_root == canonical.state_root {
            return Ok(Comparison::Match);
        }
        let incident = Incident {
            schema_version: SCHEMA_VERSION,
            effective_chain_id: self.chain_id,
            l2_block_number: local.number,
            local_hash: local.hash,
            canonical_hash: canonical.hash,
            local_state_root: local.state_root,
            canonical_state_root: canonical.state_root,
            detected_at_unix_secs: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        // A pre-existing marker means another monitor already recorded the same class of
        // incident. It must still stop this process; the marker is intentionally no-clobber.
        let _ = persist_incident(&self.incident_path, &incident)?;
        Ok(Comparison::Mismatch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Comparison {
    Match,
    Mismatch,
}

impl TrustedL2Monitor {
    #[cfg(test)]
    fn for_test(chain_id: u64, incident_path: PathBuf) -> Self {
        Self {
            chain_id,
            incident_path,
            client: HttpClientBuilder::default()
                .build("http://127.0.0.1:1")
                .expect("test URL is valid"),
        }
    }
}

#[derive(Deserialize)]
struct RemoteHeader {
    number: String,
    hash: String,
    #[serde(rename = "stateRoot")]
    state_root: String,
}

impl RemoteHeader {
    fn into_observation(self, expected_number: u64) -> eyre::Result<HeaderObservation> {
        let number = parse_quantity(&self.number)?;
        if number != expected_number {
            return Err(eyre!("remote block is not the requested height"));
        }
        Ok(HeaderObservation {
            number,
            hash: self.hash.parse().map_err(|_| eyre!("malformed remote block hash"))?,
            state_root: self.state_root.parse().map_err(|_| eyre!("malformed remote state root"))?,
        })
    }
}

fn active_incident_path(data_dir: &Path) -> PathBuf {
    data_dir.join(INCIDENT_DIR).join(ACTIVE_INCIDENT)
}

fn refuse_active_incident(path: &Path) -> eyre::Result<()> {
    if path.exists() {
        return Err(eyre!("active trusted-L2 divergence incident exists at {}", path.display()));
    }
    Ok(())
}

fn validate_chain_id(expected: u64, actual: u64) -> eyre::Result<()> {
    if expected != actual {
        return Err(eyre!("trusted L2 RPC chain id {actual} does not match effective chain id {expected}"));
    }
    Ok(())
}

fn parse_quantity(value: &str) -> eyre::Result<u64> {
    u64::from_str_radix(value.strip_prefix("0x").ok_or_else(|| eyre!("quantity is not hexadecimal"))?, 16)
        .map_err(Into::into)
}

/// Publish a no-clobber marker from a fully synced temporary file.
///
/// `hard_link` is the atomic no-replace publication primitive available in `std`; it guarantees a
/// concurrent or pre-existing active marker is never replaced. The directory is synced after both
/// publishing and temporary-file cleanup.
fn persist_incident(path: &Path, incident: &Incident) -> eyre::Result<bool> {
    let directory = path.parent().ok_or_else(|| eyre!("incident path has no parent"))?;
    fs::create_dir_all(directory)?;
    if path.exists() {
        return Ok(false);
    }
    let temporary = directory.join(format!(".active-{}-{}.tmp", std::process::id(), unique_suffix()));
    let result = (|| -> eyre::Result<bool> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(&serde_json::to_vec(incident)?)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        match fs::hard_link(&temporary, path) {
            Ok(()) => {
                sync_directory(directory)?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error.into()),
        }
    })();
    let _ = fs::remove_file(&temporary);
    let _ = sync_directory(directory);
    result
}

fn unique_suffix() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_nanos())
}

fn sync_directory(directory: &Path) -> eyre::Result<()> {
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn hash(byte: u8) -> B256 {
        B256::from([byte; 32])
    }

    fn observation(hash: B256, state_root: B256) -> HeaderObservation {
        HeaderObservation { number: 42, hash, state_root }
    }

    fn monitor(data_dir: &Path) -> TrustedL2Monitor {
        TrustedL2Monitor::for_test(1, active_incident_path(data_dir))
    }

    #[test]
    fn equal_observations_do_not_trip() {
        let data_dir = tempdir().unwrap();
        let header = observation(hash(1), hash(2));
        assert_eq!(
            monitor(data_dir.path()).compare_and_record(header, header).unwrap(),
            Comparison::Match
        );
        assert!(!active_incident_path(data_dir.path()).exists());
    }

    #[test]
    fn hash_only_mismatch_trips() {
        let data_dir = tempdir().unwrap();
        let local = observation(hash(1), hash(2));
        let canonical = observation(hash(3), hash(2));
        assert_eq!(
            monitor(data_dir.path()).compare_and_record(local, canonical).unwrap(),
            Comparison::Mismatch
        );
    }

    #[test]
    fn root_only_mismatch_trips() {
        let data_dir = tempdir().unwrap();
        let local = observation(hash(1), hash(2));
        let canonical = observation(hash(1), hash(3));
        assert_eq!(
            monitor(data_dir.path()).compare_and_record(local, canonical).unwrap(),
            Comparison::Mismatch
        );
    }

    #[test]
    fn chain_id_mismatch_is_rejected() {
        assert!(validate_chain_id(42161, 421614).is_err());
    }

    #[test]
    fn monitor_cursor_walks_each_new_height_and_rechecks_replacements() {
        let previous = observation(hash(1), hash(2));
        assert_eq!(
            first_unchecked_height(Some(previous), HeaderObservation { number: 45, ..previous })
                .unwrap(),
            Some(43)
        );
        assert_eq!(first_unchecked_height(Some(previous), previous).unwrap(), None);
        assert_eq!(
            first_unchecked_height(Some(previous), observation(hash(3), hash(2))).unwrap(),
            Some(42)
        );
        assert_eq!(
            first_unchecked_height(Some(previous), HeaderObservation { number: 41, ..previous })
                .unwrap(),
            Some(41)
        );
    }

    #[test]
    fn marker_persists_and_is_not_overwritten() {
        let data_dir = tempdir().unwrap();
        let path = active_incident_path(data_dir.path());
        let first = Incident {
            schema_version: SCHEMA_VERSION,
            effective_chain_id: 1,
            l2_block_number: 2,
            local_hash: B256::ZERO,
            canonical_hash: hash(1),
            local_state_root: B256::ZERO,
            canonical_state_root: hash(2),
            detected_at_unix_secs: 3,
        };
        let second = Incident { l2_block_number: 9, ..first };
        assert!(persist_incident(&path, &first).unwrap());
        let original = fs::read(&path).unwrap();
        assert!(!persist_incident(&path, &second).unwrap());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(!String::from_utf8(original).unwrap().contains("rpc"));
    }

    #[test]
    fn active_marker_refuses_startup() {
        let data_dir = tempdir().unwrap();
        let path = active_incident_path(data_dir.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"{}").unwrap();
        assert!(refuse_active_incident(&path).is_err());
    }
}
