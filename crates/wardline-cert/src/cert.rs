#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wardline_core::capability::{host_matches_pattern, CapabilityScope};
use wardline_core::path::{is_lexical_prefix_match, normalize_windows_lexical_path};
use wardline_core::{IsolationLevel, TargetArch};
use zeroize::ZeroizeOnDrop;

use crate::crl::CrlStore;
use crate::CertError;

const CERT_SIG_DOMAIN: &[u8] = b"wardline.cert.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityClaim {
    pub cert_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub subject: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub min_isolation: IsolationLevel,
    pub arch_constraint: Option<TargetArch>,
    pub delegation_depth_remaining: u8,
    pub holder_pubkey: [u8; 32],
    pub scopes: Vec<CapabilityScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WardCertNode {
    pub claim: CapabilityClaim,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WardCertChain {
    pub nodes: Vec<WardCertNode>,
}

#[derive(ZeroizeOnDrop)]
pub struct CertAuthority {
    signing_key: SigningKey,
}

impl CertAuthority {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue_root(
        &self,
        subject: impl Into<String>,
        holder_pubkey: [u8; 32],
        issued_at_unix: u64,
        expires_at_unix: u64,
        min_isolation: IsolationLevel,
        arch_constraint: Option<TargetArch>,
        delegation_depth: u8,
        scopes: Vec<CapabilityScope>,
    ) -> Result<WardCertChain, CertError> {
        if expires_at_unix <= issued_at_unix {
            return Err(CertError::AttenuationViolation(
                "expires_at_unix must be strictly greater than issued_at_unix".into(),
            ));
        }
        let claim = CapabilityClaim {
            cert_id: Uuid::new_v4(),
            parent_id: None,
            subject: subject.into(),
            issued_at_unix,
            expires_at_unix,
            min_isolation,
            arch_constraint,
            delegation_depth_remaining: delegation_depth,
            holder_pubkey,
            scopes,
        };
        let sig = sign_claim(&self.signing_key, &claim)?;
        Ok(WardCertChain {
            nodes: vec![WardCertNode {
                claim,
                signature: sig,
            }],
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn delegate(
        &self,
        parent: &WardCertChain,
        next_subject: impl Into<String>,
        next_holder_pubkey: [u8; 32],
        issued_at_unix: u64,
        expires_at_unix: u64,
        min_isolation: IsolationLevel,
        arch_constraint: Option<TargetArch>,
        scopes: Vec<CapabilityScope>,
    ) -> Result<WardCertChain, CertError> {
        let leaf = parent.nodes.last().ok_or(CertError::EmptyChain)?;
        if self.public_key_bytes() != leaf.claim.holder_pubkey {
            return Err(CertError::InvalidSignature);
        }
        if leaf.claim.delegation_depth_remaining == 0 {
            return Err(CertError::AttenuationViolation(
                "parent delegation_depth_remaining is exhausted".into(),
            ));
        }
        let child_claim = CapabilityClaim {
            cert_id: Uuid::new_v4(),
            parent_id: Some(leaf.claim.cert_id),
            subject: next_subject.into(),
            issued_at_unix,
            expires_at_unix,
            min_isolation,
            arch_constraint,
            delegation_depth_remaining: leaf.claim.delegation_depth_remaining - 1,
            holder_pubkey: next_holder_pubkey,
            scopes,
        };
        validate_monotonic_attenuation(&leaf.claim, &child_claim)?;
        let sig = sign_claim(&self.signing_key, &child_claim)?;
        let mut nodes = parent.nodes.clone();
        nodes.push(WardCertNode {
            claim: child_claim,
            signature: sig,
        });
        Ok(WardCertChain { nodes })
    }
}

fn encode_signing_payload(claim: &CapabilityClaim) -> Result<Vec<u8>, CertError> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(CERT_SIG_DOMAIN);
    ciborium::into_writer(claim, &mut buf).map_err(|e| CertError::Encoding(e.to_string()))?;
    Ok(buf)
}

fn sign_claim(signing_key: &SigningKey, claim: &CapabilityClaim) -> Result<Vec<u8>, CertError> {
    let payload = encode_signing_payload(claim)?;
    Ok(signing_key.sign(&payload).to_bytes().to_vec())
}

fn verify_sig(pubkey_bytes: &[u8; 32], claim: &CapabilityClaim, sig_bytes: &[u8]) -> Result<(), CertError> {
    let vk = VerifyingKey::from_bytes(pubkey_bytes).map_err(|_| CertError::InvalidSignature)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CertError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_arr);
    let payload = encode_signing_payload(claim)?;
    vk.verify(&payload, &sig)
        .map_err(|_| CertError::InvalidSignature)
}

fn is_clean_url_prefix(p: &str) -> bool {
    if !p.starts_with('/') || p.contains(['\\', '?', '#']) {
        return false;
    }
    let lc = p.to_ascii_lowercase();
    if lc.contains("%2e") || lc.contains("%2f") || lc.contains("%5c") {
        return false;
    }
    p.split('/').all(|s| s != "." && s != "..")
}

fn strip_exe_suffix_ascii(s: &str) -> String {
    let lc = s.to_ascii_lowercase();
    lc.strip_suffix(".exe").unwrap_or(&lc).to_string()
}

fn scope_subsumed_by(child: &CapabilityScope, parent: &CapabilityScope) -> bool {
    match (child, parent) {
        (CapabilityScope::FsRead { root: c }, CapabilityScope::FsRead { root: p })
        | (CapabilityScope::FsWrite { root: c }, CapabilityScope::FsWrite { root: p })
        | (CapabilityScope::FsDelete { root: c }, CapabilityScope::FsDelete { root: p }) => {
            is_lexical_prefix_match(c, p)
        }
        (CapabilityScope::FsRead { root: c }, CapabilityScope::FsWrite { root: p }) => {
            is_lexical_prefix_match(c, p)
        }
        (CapabilityScope::Exec { binary: c }, CapabilityScope::Exec { binary: p }) => {
            if p == "*" || c.eq_ignore_ascii_case(p) {
                true
            } else if !c.contains(['\\', '/', ':']) && !p.contains(['\\', '/', ':']) {
                strip_exe_suffix_ascii(c) == strip_exe_suffix_ascii(p)
            } else {
                matches!(
                    (
                        normalize_windows_lexical_path(c),
                        normalize_windows_lexical_path(p)
                    ),
                    (Ok(cn), Ok(pn)) if cn.eq_ignore_ascii_case(&pn)
                )
            }
        }
        (
            CapabilityScope::Net {
                host_pattern: ch,
                path_prefix: cp,
            },
            CapabilityScope::Net {
                host_pattern: ph,
                path_prefix: pp,
            },
        ) => {
            let host_ok = if ch.eq_ignore_ascii_case(ph) {
                true
            } else if let Some(stripped) = ch.strip_prefix("*.") {
                ph.starts_with("*.")
                    && !stripped.is_empty()
                    && !stripped.starts_with('.')
                    && !stripped.contains('*')
                    && host_matches_pattern(stripped, ph)
            } else if !ch.starts_with('*') {
                !ch.is_empty()
                    && !ch.starts_with('.')
                    && !ch.contains('*')
                    && host_matches_pattern(ch, ph)
            } else {
                false
            };
            let pp_trim = pp.trim_end_matches('/');
            let cp_trim = cp.trim_end_matches('/');
            let path_ok = is_clean_url_prefix(cp)
                && is_clean_url_prefix(pp)
                && (cp == pp
                    || pp == "/"
                    || cp_trim == pp_trim
                    || cp_trim.starts_with(&format!("{pp_trim}/")));
            host_ok && path_ok
        }
        (CapabilityScope::VaultGrant { grant_id: c }, CapabilityScope::VaultGrant { grant_id: p }) => {
            c == p
        }
        _ => false,
    }
}

fn validate_monotonic_attenuation(
    parent: &CapabilityClaim,
    child: &CapabilityClaim,
) -> Result<(), CertError> {
    if child.parent_id != Some(parent.cert_id) {
        return Err(CertError::AttenuationViolation(
            "child parent_id does not match parent cert_id".into(),
        ));
    }
    if child.issued_at_unix < parent.issued_at_unix {
        return Err(CertError::AttenuationViolation(
            "child issued_at_unix predates parent".into(),
        ));
    }
    if child.expires_at_unix > parent.expires_at_unix {
        return Err(CertError::AttenuationViolation(
            "child cannot extend expiry beyond parent".into(),
        ));
    }
    if child.expires_at_unix <= child.issued_at_unix {
        return Err(CertError::AttenuationViolation(
            "child expires_at_unix must exceed issued_at_unix".into(),
        ));
    }
    if child.min_isolation < parent.min_isolation {
        return Err(CertError::AttenuationViolation(
            "child cannot weaken isolation requirement below parent".into(),
        ));
    }
    if parent.delegation_depth_remaining == 0
        || child.delegation_depth_remaining >= parent.delegation_depth_remaining
    {
        return Err(CertError::AttenuationViolation(
            "child must strictly decrement delegation depth".into(),
        ));
    }
    if let Some(p_arch) = parent.arch_constraint {
        if child.arch_constraint != Some(p_arch) {
            return Err(CertError::AttenuationViolation(
                "child cannot widen or switch architecture constraint".into(),
            ));
        }
    }
    for scope in &child.scopes {
        if !parent.scopes.iter().any(|p| scope_subsumed_by(scope, p)) {
            return Err(CertError::AttenuationViolation(format!(
                "child scope {scope:?} exceeds parent caveats"
            )));
        }
    }
    Ok(())
}

pub fn verify_cert_chain<'a>(
    root_pubkey: &[u8; 32],
    chain: &'a WardCertChain,
    crl: Option<&CrlStore>,
    now_unix: u64,
) -> Result<&'a CapabilityClaim, CertError> {
    let first = chain.nodes.first().ok_or(CertError::EmptyChain)?;
    if first.claim.parent_id.is_some() {
        return Err(CertError::AttenuationViolation(
            "root certificate cannot declare parent_id".into(),
        ));
    }

    let mut signer_pubkey = *root_pubkey;
    let mut prev_claim: Option<&CapabilityClaim> = None;

    for node in &chain.nodes {
        verify_sig(&signer_pubkey, &node.claim, &node.signature)?;

        if now_unix < node.claim.issued_at_unix {
            return Err(CertError::NotYetValid {
                not_before: node.claim.issued_at_unix,
                now: now_unix,
            });
        }
        if now_unix > node.claim.expires_at_unix {
            return Err(CertError::Expired {
                expired_at: node.claim.expires_at_unix,
                now: now_unix,
            });
        }
        if let Some(store) = crl {
            if store.is_revoked(node.claim.cert_id)? {
                return Err(CertError::Revoked(node.claim.cert_id));
            }
        }
        if let Some(parent) = prev_claim {
            validate_monotonic_attenuation(parent, &node.claim)?;
        }

        signer_pubkey = node.claim.holder_pubkey;
        prev_claim = Some(&node.claim);
    }

    Ok(&chain.nodes.last().expect("non-empty chain").claim)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_exec_and_subdomain_net_attenuate_monotonically() {
        let root = CertAuthority::generate();
        let worker = CertAuthority::generate();
        let leaf = CertAuthority::generate();

        let parent = root
            .issue_root(
                "orchestrator",
                worker.public_key_bytes(),
                1000,
                2000,
                IsolationLevel::L1,
                None,
                2,
                vec![
                    CapabilityScope::Exec { binary: "*".into() },
                    CapabilityScope::Net {
                        host_pattern: "*.github.com".into(),
                        path_prefix: "/".into(),
                    },
                ],
            )
            .unwrap();

        let child = worker
            .delegate(
                &parent,
                "worker-step",
                leaf.public_key_bytes(),
                1100,
                1500,
                IsolationLevel::L1,
                None,
                vec![
                    CapabilityScope::Exec {
                        binary: "whoami.exe".into(),
                    },
                    CapabilityScope::Net {
                        host_pattern: "*.api.github.com".into(),
                        path_prefix: "/repos".into(),
                    },
                ],
            )
            .unwrap();

        let claim = verify_cert_chain(&root.public_key_bytes(), &child, None, 1200).unwrap();
        assert_eq!(claim.subject, "worker-step");

        let exact_parent = root
            .issue_root(
                "exact-host",
                worker.public_key_bytes(),
                1000,
                2000,
                IsolationLevel::L1,
                None,
                2,
                vec![CapabilityScope::Net {
                    host_pattern: "api.github.com".into(),
                    path_prefix: "/".into(),
                }],
            )
            .unwrap();
        let widened = worker.delegate(
            &exact_parent,
            "widened-sub",
            leaf.public_key_bytes(),
            1100,
            1500,
            IsolationLevel::L1,
            None,
            vec![CapabilityScope::Net {
                host_pattern: "*.api.github.com".into(),
                path_prefix: "/".into(),
            }],
        );
        assert!(widened.is_err());
    }
}
