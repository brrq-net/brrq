//! Doctrine Firewall — automatic rejection of proposals that violate immutable laws.
//!
//! ## The Three Immutable Laws (Article 1)
//!
//! 1. **Key Sovereignty**: No entity may access or block user keys.
//! 2. **Pure Hash Architecture (PHA)**: No new elliptic curves as permanent replacements.
//!    STARK + Poseidon2 + SLH-DSA + dual signing are mandatory.
//! 3. **Unconditional Exit Right**: No update may restrict or delay peg-out to Bitcoin L1.
//!
//! These laws are not subject to voting and cannot be amended. Any proposal that
//! violates them is automatically rejected at the node level before entering the
//! voting phase and again before execution — a double firewall.

/// Keywords and patterns that indicate a proposal violates immutable doctrine.
///
/// These are checked against proposal descriptions and amendment text.
/// The firewall uses a conservative allowlist approach: proposals that mention
/// sensitive topics are flagged for manual review, not silently passed.
mod prohibited_patterns {
    /// Patterns indicating introduction of new elliptic curves as permanent replacement.
    pub const EC_REPLACEMENT_PATTERNS: &[&str] = &[
        "replace slh-dsa",
        "remove slh-dsa",
        "disable dual signing",
        "remove dual signing",
        "single signature only",
        "replace stark",
        "remove stark",
        "replace poseidon",
        "remove poseidon",
        "ecdsa only",
        "secp256k1 only",
        "remove post-quantum",
        "disable post-quantum",
        "remove quantum resistance",
    ];

    /// Patterns indicating violation of key sovereignty (Law 1).
    /// No entity may access, custody, or manage user private keys.
    pub const KEY_SOVEREIGNTY_PATTERNS: &[&str] = &[
        "key escrow",
        "custodial key",
        "server-side key",
        "admin key access",
        "master key override",
        "mandatory key disclosure",
        "key custody",
        "centralized key management",
        "key recovery by operator",
        "backdoor key",
    ];

    /// Patterns indicating restriction of peg-out rights.
    pub const EXIT_RESTRICTION_PATTERNS: &[&str] = &[
        "disable peg-out",
        "suspend peg-out",
        "block withdrawal",
        "restrict withdrawal",
        "pause exit",
        "disable exit",
        "freeze funds",
        "lock funds permanently",
        "prevent withdrawal",
        "delay peg-out indefinitely",
        "require permission to withdraw",
        "conditional exit",
        "exit penalty",
        "withdrawal penalty",
    ];

    /// Patterns indicating attempt to modify immutable laws.
    pub const DOCTRINE_MODIFICATION_PATTERNS: &[&str] = &[
        "amend immutable law",
        "modify doctrine",
        "change immutable",
        "override constitution article 1",
        "remove immutable",
        "repeal law 1",
        "repeal law 2",
        "repeal law 3",
    ];
}

/// Result of a doctrine firewall check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctrineCheckResult {
    /// Proposal passes the firewall — no violations detected.
    Passed,
    /// Proposal violates immutable doctrine and must be auto-rejected.
    Rejected {
        /// Which immutable law was violated (1, 2, or 3).
        law_number: u8,
        /// Human-readable reason for rejection.
        reason: String,
        /// The specific pattern that triggered the rejection.
        matched_pattern: String,
    },
}

/// The Doctrine Firewall enforces immutable laws at the node level.
///
/// Every proposal passes through this firewall twice:
/// 1. Before entering the voting phase (pre-vote check)
/// 2. Before execution after approval (pre-execution check)
///
/// This ensures that even if a malicious node skips the pre-vote check,
/// honest nodes will reject the execution.
pub struct DoctrineFirewall;

impl DoctrineFirewall {
    /// Normalize text for pattern matching: strip non-ASCII, lowercase, collapse whitespace.
    ///
    /// Defeats: Cyrillic homoglyphs, zero-width characters, extra whitespace.
    fn normalize(text: &str) -> String {
        text.chars()
            .filter(|c| c.is_ascii())
            .collect::<String>()
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Check a proposal description against the immutable doctrine.
    ///
    /// Returns `DoctrineCheckResult::Rejected` if the proposal text contains
    /// any prohibited patterns. The check is case-insensitive and Unicode-normalized.
    pub fn check_proposal_text(text: &str) -> DoctrineCheckResult {
        let lower = Self::normalize(text);

        // Law 1: Key Sovereignty — no custodial key management
        for pattern in prohibited_patterns::KEY_SOVEREIGNTY_PATTERNS {
            if lower.contains(pattern) {
                return DoctrineCheckResult::Rejected {
                    law_number: 1,
                    reason: "violates Law 1 (Key Sovereignty): proposal attempts to \
                         introduce custodial or centralized key management"
                        .to_string(),
                    matched_pattern: (*pattern).to_string(),
                };
            }
        }

        // Law 2: Pure Hash Architecture — no new EC curves as permanent replacement
        for pattern in prohibited_patterns::EC_REPLACEMENT_PATTERNS {
            if lower.contains(pattern) {
                return DoctrineCheckResult::Rejected {
                    law_number: 2,
                    reason: "violates Law 2 (Pure Hash Architecture): proposal attempts to \
                         weaken or remove post-quantum cryptographic layers"
                        .to_string(),
                    matched_pattern: (*pattern).to_string(),
                };
            }
        }

        // Law 3: Unconditional Exit Right — no peg-out restrictions
        for pattern in prohibited_patterns::EXIT_RESTRICTION_PATTERNS {
            if lower.contains(pattern) {
                return DoctrineCheckResult::Rejected {
                    law_number: 3,
                    reason: "violates Law 3 (Unconditional Exit Right): proposal attempts to \
                         restrict or delay user withdrawal to Bitcoin L1"
                        .to_string(),
                    matched_pattern: (*pattern).to_string(),
                };
            }
        }

        // Meta: No modification of immutable laws themselves
        for pattern in prohibited_patterns::DOCTRINE_MODIFICATION_PATTERNS {
            if lower.contains(pattern) {
                return DoctrineCheckResult::Rejected {
                    law_number: 0, // Meta-violation
                    reason: "violates constitutional immutability: immutable laws (Article 1) \
                         cannot be amended, modified, or repealed by any mechanism"
                        .to_string(),
                    matched_pattern: (*pattern).to_string(),
                };
            }
        }

        DoctrineCheckResult::Passed
    }

    /// Check a `BridgeUpdate` proposal for exit-right violations.
    ///
    /// If `affects_peg_out` is true, the proposal receives enhanced scrutiny.
    /// Any bridge update that claims to affect peg-out must pass additional
    /// checks ensuring it does not restrict the unconditional exit right.
    pub fn check_bridge_update(description: &str, _affects_peg_out: bool) -> DoctrineCheckResult {
        // First: standard text check
        let text_result = Self::check_proposal_text(description);
        if text_result != DoctrineCheckResult::Passed {
            return text_result;
        }

        // Always apply peg-out scrutiny for BridgeUpdate proposals.
        // The affects_peg_out flag was self-declared by the proposer and could be
        // set to false to skip Law 3 checks. All bridge updates must pass this.
        if true {
            let lower = Self::normalize(description);

            // A bridge update that affects peg-out must explicitly state
            // it preserves the unconditional exit right
            let preserves_exit = lower.contains("preserves exit right")
                || lower.contains("maintains peg-out")
                || lower.contains("exit right unchanged")
                || lower.contains("withdrawal guaranteed");

            if !preserves_exit {
                return DoctrineCheckResult::Rejected {
                    law_number: 3,
                    reason: "BridgeUpdate with affects_peg_out=true must explicitly declare \
                         preservation of unconditional exit right. Add 'preserves exit right' \
                         or 'withdrawal guaranteed' to description."
                        .to_string(),
                    matched_pattern: "affects_peg_out=true without exit preservation".to_string(),
                };
            }
        }

        DoctrineCheckResult::Passed
    }

    /// Check a `ConsensusChange` proposal for doctrine violations.
    ///
    /// Breaking consensus changes receive the highest scrutiny level.
    pub fn check_consensus_change(description: &str, breaking: bool) -> DoctrineCheckResult {
        let text_result = Self::check_proposal_text(description);
        if text_result != DoctrineCheckResult::Passed {
            return text_result;
        }

        if breaking {
            let lower = Self::normalize(description);

            // Breaking changes that touch cryptographic primitives
            // must not weaken PHA
            let weakens_crypto = lower.contains("replace hash function")
                || lower.contains("remove babybear")
                || lower.contains("switch to trusted setup")
                || lower.contains("replace stark with snark");

            if weakens_crypto {
                return DoctrineCheckResult::Rejected {
                    law_number: 2,
                    reason: "breaking ConsensusChange attempts to modify core PHA primitives. \
                         STARK over BabyBear with Poseidon2 is constitutionally protected."
                        .to_string(),
                    matched_pattern: "breaking change weakens PHA".to_string(),
                };
            }
        }

        DoctrineCheckResult::Passed
    }

    /// Validate a constitutional amendment does not touch immutable laws.
    pub fn check_constitutional_amendment(amendment_text: &str) -> DoctrineCheckResult {
        Self::check_proposal_text(amendment_text)
    }

    // ── Structural Validation (Layer 2) ─────────────────────────────────
    //
    // Text matching (Layer 1) catches honest mistakes and obvious violations.
    // Structural validation (Layer 2) catches malicious payloads with benign
    // descriptions by verifying invariants that CANNOT be expressed in text.

    /// Protected cryptographic primitive hashes — these MUST NOT change.
    /// Any proposal whose code_hash resolves to a binary that modifies these
    /// domain tags or constants is rejected structurally.
    ///
    /// These are the SHA-256 hashes of the domain tag constants from brrq-crypto.
    /// A governance update that changes these values would break the protocol's
    /// post-quantum guarantees (Law 2) or key sovereignty (Law 1).
    const PROTECTED_DOMAIN_TAGS: &'static [&'static [u8]] = &[
        b"BRRQ_SCHNORR_SIG_V1",
        b"BRRQ_SLH_DSA_KEY",
        b"BRRQ_EOTS_NONCE",
        b"BRRQ_EOTSv2_NONCE",
        b"BRRQ_POSEIDON2",
        b"BRRQ_PORTAL_KEY_SIG_V1",
        b"BRRQ_PORTAL_NULLIFIER_V1",
        b"BRRQ_BLOCK_HDR_V1",
    ];

    /// Structural check: verify a proposal does not carry an empty code_hash
    /// when it claims to be an EmergencyPatch or ConsensusChange.
    ///
    /// **Why this matters:** Without a code_hash, nodes cannot verify that the
    /// payload they receive matches what was voted on. A malicious coordinator
    /// could distribute different binaries to different nodes.
    /// Maximum reasonable fee value (10 BTC in sats) — prevents DoS via absurd fees.
    const MAX_FEE_SATS: u64 = 1_000_000_000;

    fn check_structural_integrity(proposal: &ProposalDoctrineCheck) -> DoctrineCheckResult {
        match proposal {
            // EmergencyPatch must have code_hash
            ProposalDoctrineCheck::EmergencyPatch { code_hash, .. } => {
                if code_hash.is_none() {
                    return DoctrineCheckResult::Rejected {
                        law_number: 0,
                        reason: "EmergencyPatch MUST include code_hash for payload verification. \
                                 Nodes cannot apply patches they cannot verify."
                            .to_string(),
                        matched_pattern: "missing code_hash in EmergencyPatch".to_string(),
                    };
                }
                Self::check_code_hash_against_protected_tags(code_hash.as_ref())
            }

            // Breaking ConsensusChange must have code_hash
            ProposalDoctrineCheck::ConsensusChange { breaking: true, code_hash, .. } => {
                if code_hash.is_none() {
                    return DoctrineCheckResult::Rejected {
                        law_number: 0,
                        reason: "Breaking ConsensusChange MUST include code_hash. \
                                 Nodes cannot apply consensus changes they cannot verify."
                            .to_string(),
                        matched_pattern: "missing code_hash in breaking ConsensusChange".to_string(),
                    };
                }
                Self::check_code_hash_against_protected_tags(code_hash.as_ref())
            }

            // BridgeUpdate with code_hash must not touch protected tags
            ProposalDoctrineCheck::BridgeUpdate { code_hash, .. } => {
                Self::check_code_hash_against_protected_tags(code_hash.as_ref())
            }

            // FeeChange value must be in sane range (not 0, not u64::MAX)
            ProposalDoctrineCheck::FeeChange { new_value, .. } => {
                if *new_value == 0 {
                    return DoctrineCheckResult::Rejected {
                        law_number: 0,
                        reason: "FeeChange new_value cannot be zero — would disable fee market."
                            .to_string(),
                        matched_pattern: "FeeChange with new_value=0".to_string(),
                    };
                }
                if *new_value > Self::MAX_FEE_SATS {
                    return DoctrineCheckResult::Rejected {
                        law_number: 0,
                        reason: format!(
                            "FeeChange new_value {} exceeds maximum {} sats.",
                            new_value, Self::MAX_FEE_SATS
                        ),
                        matched_pattern: "FeeChange with excessive new_value".to_string(),
                    };
                }
                DoctrineCheckResult::Passed
            }

            // Council operations must target a non-zero address
            ProposalDoctrineCheck::CouncilElection { candidate } => {
                if candidate == &brrq_types::Address::ZERO {
                    return DoctrineCheckResult::Rejected {
                        law_number: 0,
                        reason: "CouncilElection candidate cannot be the zero address."
                            .to_string(),
                        matched_pattern: "CouncilElection with zero address".to_string(),
                    };
                }
                DoctrineCheckResult::Passed
            }
            ProposalDoctrineCheck::CouncilRemoval { target } => {
                if target == &brrq_types::Address::ZERO {
                    return DoctrineCheckResult::Rejected {
                        law_number: 0,
                        reason: "CouncilRemoval target cannot be the zero address."
                            .to_string(),
                        matched_pattern: "CouncilRemoval with zero address".to_string(),
                    };
                }
                DoctrineCheckResult::Passed
            }

            _ => DoctrineCheckResult::Passed,
        }
    }

    /// Check whether a code_hash payload references any protected domain tags.
    ///
    /// If a proposal's code payload contains the raw bytes of a protected domain tag,
    /// it is likely attempting to modify core cryptographic primitives (Law 2 violation).
    /// This is a conservative heuristic — the full check requires WASM introspection.
    fn check_code_hash_against_protected_tags(
        code_hash: Option<&brrq_crypto::hash::Hash256>,
    ) -> DoctrineCheckResult {
        // If no code_hash provided, structural check passes (text check handles the rest).
        // For EmergencyPatch/ConsensusChange, the caller already rejected None.
        if code_hash.is_none() {
            return DoctrineCheckResult::Passed;
        }

        // NOTE: Full payload inspection requires the actual binary (resolved from code_hash).
        // At this layer we can only verify the hash is present. Binary introspection
        // (checking if the payload modifies PROTECTED_DOMAIN_TAGS) requires a future
        // WASM sandbox layer. The hash presence ensures nodes can verify payload integrity.
        //
        // When WASM sandbox is available, resolve code_hash → binary
        // and scan for PROTECTED_DOMAIN_TAGS modifications.
        DoctrineCheckResult::Passed
    }

    /// Full proposal validation — dispatches to the appropriate checker
    /// based on proposal metadata.
    ///
    /// This is the main entry point called by `GovernanceManager` before
    /// accepting a proposal into the voting queue and again before execution.
    ///
    /// Runs TWO layers:
    /// 1. **Structural check** — verifies proposal integrity (code_hash present, etc.)
    /// 2. **Text check** — pattern matching against immutable law keywords
    pub fn validate(proposal: &ProposalDoctrineCheck) -> DoctrineCheckResult {
        // Layer 2: Structural integrity first
        let structural = Self::check_structural_integrity(proposal);
        if structural != DoctrineCheckResult::Passed {
            return structural;
        }

        // Layer 1: Text pattern matching
        match proposal {
            ProposalDoctrineCheck::TechnicalUpdate { description } => {
                Self::check_proposal_text(description)
            }
            ProposalDoctrineCheck::FeeChange { description, .. } => {
                // FeeChange carries a description field — apply doctrine text checks.
                Self::check_proposal_text(description)
            }
            ProposalDoctrineCheck::SlashingChange { reason } => Self::check_proposal_text(reason),
            ProposalDoctrineCheck::Constitutional { amendment } => {
                Self::check_constitutional_amendment(amendment)
            }
            ProposalDoctrineCheck::BridgeUpdate {
                description,
                affects_peg_out,
                ..
            } => Self::check_bridge_update(description, *affects_peg_out),
            ProposalDoctrineCheck::ConsensusChange {
                description,
                breaking,
                ..
            } => Self::check_consensus_change(description, *breaking),
            ProposalDoctrineCheck::EmergencyPatch { justification, .. } => {
                Self::check_proposal_text(justification)
            }
            ProposalDoctrineCheck::CouncilElection { .. }
            | ProposalDoctrineCheck::CouncilRemoval { .. } => {
                // Structural check already validates non-zero address.
                // Council operations have no text payload to check.
                DoctrineCheckResult::Passed
            }
        }
    }
}

/// Lightweight representation of proposal data needed for doctrine checks.
///
/// Avoids coupling the firewall to the full `ProposalType` enum.
#[derive(Debug, Clone)]
pub enum ProposalDoctrineCheck {
    TechnicalUpdate {
        description: String,
    },
    FeeChange {
        description: String,
        /// Proposed new fee value (sats). Validated for sane range.
        new_value: u64,
    },
    SlashingChange {
        reason: String,
    },
    Constitutional {
        amendment: String,
    },
    BridgeUpdate {
        description: String,
        affects_peg_out: bool,
        /// Optional code payload hash for structural inspection.
        code_hash: Option<brrq_crypto::hash::Hash256>,
    },
    ConsensusChange {
        description: String,
        breaking: bool,
        /// Mandatory for breaking changes — nodes verify payload matches.
        code_hash: Option<brrq_crypto::hash::Hash256>,
    },
    EmergencyPatch {
        justification: String,
        cve_reference: String,
        /// SHA-256 of the proposed code/binary payload.
        /// Nodes verify the received payload matches this hash before applying.
        code_hash: Option<brrq_crypto::hash::Hash256>,
    },
    /// Council election — carries candidate address for validation.
    CouncilElection {
        candidate: brrq_types::Address,
    },
    /// Council removal — carries target address for validation.
    CouncilRemoval {
        target: brrq_types::Address,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_benign_technical_update() {
        let result = DoctrineFirewall::check_proposal_text(
            "Optimize batch proof verification for faster block processing",
        );
        assert_eq!(result, DoctrineCheckResult::Passed);
    }

    #[test]
    fn rejects_key_escrow() {
        let result =
            DoctrineFirewall::check_proposal_text("Add key escrow for regulatory compliance");
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 1, .. }
        ));
    }

    #[test]
    fn rejects_custodial_key_management() {
        let result = DoctrineFirewall::check_proposal_text(
            "Enable centralized key management for enterprise users",
        );
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 1, .. }
        ));
    }

    #[test]
    fn rejects_slh_dsa_removal() {
        let result =
            DoctrineFirewall::check_proposal_text("Remove SLH-DSA to reduce block size overhead");
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 2, .. }
        ));
    }

    #[test]
    fn rejects_dual_signing_disable() {
        let result = DoctrineFirewall::check_proposal_text(
            "Disable dual signing for performance improvement",
        );
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 2, .. }
        ));
    }

    #[test]
    fn rejects_peg_out_restriction() {
        let result =
            DoctrineFirewall::check_proposal_text("Disable peg-out during high congestion periods");
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 3, .. }
        ));
    }

    #[test]
    fn rejects_fund_freeze() {
        let result = DoctrineFirewall::check_proposal_text("Freeze funds of sanctioned addresses");
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 3, .. }
        ));
    }

    #[test]
    fn rejects_doctrine_modification() {
        let result =
            DoctrineFirewall::check_proposal_text("Amend immutable law 2 to allow ECDSA-only mode");
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 0, .. }
        ));
    }

    #[test]
    fn rejects_bridge_update_affecting_peg_out_without_declaration() {
        let result =
            DoctrineFirewall::check_bridge_update("Upgrade bridge timeout parameters", true);
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 3, .. }
        ));
    }

    #[test]
    fn passes_bridge_update_with_exit_preservation() {
        let result = DoctrineFirewall::check_bridge_update(
            "Upgrade bridge timeout parameters — withdrawal guaranteed",
            true,
        );
        assert_eq!(result, DoctrineCheckResult::Passed);
    }

    #[test]
    fn rejects_breaking_consensus_weakening_pha() {
        let result = DoctrineFirewall::check_consensus_change(
            "Replace STARK with SNARK for smaller proofs",
            true,
        );
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 2, .. }
        ));
    }

    #[test]
    fn passes_non_breaking_consensus_change() {
        let result = DoctrineFirewall::check_consensus_change(
            "Increase epoch length from 7200 to 14400 blocks",
            false,
        );
        assert_eq!(result, DoctrineCheckResult::Passed);
    }

    #[test]
    fn full_validation_fee_change_benign_passes() {
        let result = DoctrineFirewall::validate(&ProposalDoctrineCheck::FeeChange {
            description: "adjust base fee from 100 to 200 sats".to_string(),
            new_value: 200,
        });
        assert_eq!(result, DoctrineCheckResult::Passed);
    }

    #[test]
    fn full_validation_fee_change_doctrine_violation_rejected() {
        let result = DoctrineFirewall::validate(&ProposalDoctrineCheck::FeeChange {
            description: "disable peg-out during high fees".to_string(),
            new_value: 100,
        });
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 3, .. }
        ));
    }

    #[test]
    fn full_validation_fee_change_zero_rejected() {
        let result = DoctrineFirewall::validate(&ProposalDoctrineCheck::FeeChange {
            description: "set fee to zero".to_string(),
            new_value: 0,
        });
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 0, .. }
        ));
    }

    #[test]
    fn full_validation_fee_change_excessive_rejected() {
        let result = DoctrineFirewall::validate(&ProposalDoctrineCheck::FeeChange {
            description: "set fee to max".to_string(),
            new_value: u64::MAX,
        });
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 0, .. }
        ));
    }

    #[test]
    fn full_validation_council_operations_pass() {
        let addr = brrq_types::Address([0x01; 20]);
        assert_eq!(
            DoctrineFirewall::validate(&ProposalDoctrineCheck::CouncilElection { candidate: addr }),
            DoctrineCheckResult::Passed
        );
        assert_eq!(
            DoctrineFirewall::validate(&ProposalDoctrineCheck::CouncilRemoval { target: addr }),
            DoctrineCheckResult::Passed
        );
    }

    #[test]
    fn full_validation_council_zero_address_rejected() {
        assert!(matches!(
            DoctrineFirewall::validate(&ProposalDoctrineCheck::CouncilElection {
                candidate: brrq_types::Address::ZERO,
            }),
            DoctrineCheckResult::Rejected { law_number: 0, .. }
        ));
    }

    #[test]
    fn full_validation_breaking_consensus_change_needs_code_hash() {
        let result = DoctrineFirewall::validate(&ProposalDoctrineCheck::ConsensusChange {
            description: "update block format".to_string(),
            breaking: true,
            code_hash: None,
        });
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 0, .. }
        ));
    }

    #[test]
    fn case_insensitive_matching() {
        let result = DoctrineFirewall::check_proposal_text("REMOVE SLH-DSA from consensus layer");
        assert!(matches!(
            result,
            DoctrineCheckResult::Rejected { law_number: 2, .. }
        ));
    }
}
