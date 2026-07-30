//! Which generation of the Orchard Action circuit a transaction's bundle uses.
//!
//! The Action circuit is versioned: NU6.3 added the cross-address gadget, so from
//! that branch an Orchard bundle is `orchard_v3` and its proofs only satisfy the
//! `PostNu6_3` circuit. Crucially this follows the **epoch the bundle is mined in,
//! not the transaction version** — a V5 transaction built past NU6.3 carries an
//! `orchard_v3` bundle just like a V6 one.
//!
//! Proving and verifying must agree on that generation: a proof made with one
//! generation's key fails verification against the other (`InvalidInstances`).
//! `craft` and `finalize` therefore derive it from the same function here rather
//! than each holding its own copy of the rule.

use orchard::{circuit::OrchardCircuitVersion, ValuePool};
use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;
use zcash_protocol::consensus::BranchId;

/// The Orchard circuit generation in force on `branch`.
///
/// Branches with no Orchard bundle version fall back to the pre-NU6.3 generation,
/// which is also what every branch from NU5 to NU6.2 maps to.
pub(crate) fn orchard_circuit_version_for(branch: BranchId) -> OrchardCircuitVersion {
    match bundle_version_for_branch(branch, ValuePool::Orchard).map(|v| v.circuit_version()) {
        Some(OrchardCircuitVersion::PostNu6_3) => OrchardCircuitVersion::PostNu6_3,
        _ => OrchardCircuitVersion::FixedPostNu6_2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NU6.3 is where the cross-address gadget lands, so it — and nothing before
    /// it — selects the new circuit generation. Both key selectors in `craft` and
    /// `finalize` hang off this mapping.
    #[test]
    fn nu6_3_selects_the_new_generation_and_earlier_branches_do_not() {
        assert_eq!(
            orchard_circuit_version_for(BranchId::Nu6_3),
            OrchardCircuitVersion::PostNu6_3
        );

        for branch in [
            BranchId::Nu5,
            BranchId::Nu6,
            BranchId::Nu6_1,
            BranchId::Nu6_2,
        ] {
            assert_eq!(
                orchard_circuit_version_for(branch),
                OrchardCircuitVersion::FixedPostNu6_2,
                "{branch:?} predates the cross-address gadget"
            );
        }
    }

    /// Branches with no Orchard pool at all must not be treated as NU6.3.
    #[test]
    fn pre_orchard_branches_fall_back_to_the_old_generation() {
        for branch in [BranchId::Sprout, BranchId::Sapling, BranchId::Canopy] {
            assert_eq!(
                orchard_circuit_version_for(branch),
                OrchardCircuitVersion::FixedPostNu6_2,
                "{branch:?} has no Orchard bundle"
            );
        }
    }
}
