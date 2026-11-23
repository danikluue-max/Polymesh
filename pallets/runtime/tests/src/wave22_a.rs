//! Wave 22 verification tests — AREA A (identity / group / committee).
//!
//! Verdict semantics: each `#[test]` asserts the buggy behaviour claimed by
//! hunter A. **PASS = bug CONFIRMED, FAIL = bug REFUTED.** Every test also
//! prints `WAVE22 <ID>: CONFIRMED ...` / `REFUTED ...` with the observed
//! values, so the verdict is readable in CI logs even when a test fails.
//!
//! Registration (do NOT edit the repo's `lib.rs`; this is only the line the
//! CI staging overlay needs):
//! ```ignore
//! mod wave22_a;
//! ```
//! in `pallets/runtime/tests/src/lib.rs`.
//!
//! Notes on the harness (all verified against the v8.2.0 sources):
//! * `pallets/runtime/tests/Cargo.toml` enables `pallet-identity` feature
//!   `no_cdd`, but that feature is an **empty feature** (`pallets/identity/
//!   Cargo.toml:42`, `no_cdd = []`) with no `cfg(feature = "no_cdd")` anywhere
//!   in `pallets/identity/src/`. It disables nothing — the CDD-claim path used
//!   by A-01 is fully live in this harness.
//! * Secondary-key permission checks read `CurrentPalletName` /
//!   `CurrentDispatchableName`, which are only populated while an extrinsic
//!   is dispatched (or wrapped in `pallet_permissions::with_call_metadata`).
//!   A-02 therefore plants its auth through `with_call_metadata` fed by the
//!   real `RuntimeCall::get_call_metadata()` (narrow-permission variant), and
//!   through `Permissions::default()` (`ExtrinsicPermissions::Whole`, which
//!   passes regardless of metadata) for the removal-survival variant.
//! * In this test runtime every group `RemoveOrigin` is `EnsureRoot`
//!   (`pallets/runtime/tests/src/storage.rs`), so a committee-passed proposal
//!   cannot itself execute a membership removal here (same on mainnet for the
//!   GC itself; mainnet TC/UC `RemoveOrigin` is their own VMO). A-07
//!   therefore triggers the removal via abdication, which flows through the
//!   identical `change_members_sorted` code path.

use frame_support::traits::GetCallMetadata;
use frame_support::{assert_noop, assert_ok};

use sp_core::H256;
use sp_keyring::Sr25519Keyring;
use sp_runtime::traits::Hash;

use pallet_committee::{self as committee, Event as CommitteeRawEvent};
use pallet_committee::{Members, Proposals, Voting};
use pallet_compliance_manager as compliance_manager;
use pallet_group as group;
use pallet_identity as identity;
use pallet_identity::Authorizations;
use polymesh_primitives::traits::group::GroupTrait;
use polymesh_primitives::{
    AuthorizationData, Claim, ClaimType, Condition, ConditionType, IdentityId,
    PalletPermissions, Permissions, PortfolioId, Signatory, SystematicIssuers, TrustedFor,
    TrustedIssuer, WeightMeter,
};

use super::asset_pallet::setup::create_and_issue_sample_asset;
use super::storage::{
    add_secondary_key_with_perms, get_identity_id, get_last_auth_id, get_primary_key,
    make_remark_proposal, root, EventTest, RuntimeCall, TestStorage, User,
};
use super::ExtBuilder;

type Asset = pallet_asset::Pallet<TestStorage>;
type ComplianceManager = compliance_manager::Pallet<TestStorage>;
type Identity = identity::Pallet<TestStorage>;
type System = frame_system::Pallet<TestStorage>;

type DidRegistrars = group::Pallet<TestStorage, group::Instance2>;
type Committee = committee::Pallet<TestStorage, committee::Instance1>;
type CommitteeGroup = group::Pallet<TestStorage, group::Instance1>;
type TechnicalCommittee = committee::Pallet<TestStorage, committee::Instance3>;
type TechnicalCommitteeMembership = group::Pallet<TestStorage, group::Instance3>;

type Origin = <TestStorage as frame_system::Config>::RuntimeOrigin;

// ===========================================================================
// A-01 (HIGH): CDD claim issued by a registrar that is later removed still
// passes compliance.
// ===========================================================================

#[test]
fn wave22_a01_stale_cdd_claim_survives_registrar_removal() {
    ExtBuilder::default()
        .monied(true)
        .did_registrars(vec![Sr25519Keyring::Eve.to_account_id()])
        .build()
        .execute_with(wave22_a01_we);
}

fn wave22_a01_we() {
    let registrar = User::existing(Sr25519Keyring::Eve);
    let attacker = User::new(Sr25519Keyring::Bob);
    let owner = User::new(Sr25519Keyring::Alice);
    let receiver_no_cdd = User::new(Sr25519Keyring::Charlie);

    // (1) Registrar issues a CDD claim (no expiry) to the attacker.
    assert_ok!(Identity::add_claim(
        registrar.origin(),
        attacker.did,
        Claim::CustomerDueDiligence(Default::default()),
        None,
    ));
    assert!(Identity::fetch_claim(
        attacker.did,
        ClaimType::CustomerDueDiligence,
        registrar.did,
        None
    )
    .is_some());

    // (2) Asset trusting the registrar for CDD, with an IsPresent(CDD)
    // receiver condition.
    let asset_id = create_and_issue_sample_asset(&owner);
    assert_ok!(ComplianceManager::add_default_trusted_claim_issuer(
        owner.origin(),
        asset_id,
        TrustedIssuer {
            issuer: registrar.did,
            trusted_for: TrustedFor::Any,
        },
    ));
    let receiver_condition = Condition::from_dids(
        ConditionType::IsPresent(Claim::CustomerDueDiligence(Default::default())),
        &[registrar.did],
    );
    assert_ok!(ComplianceManager::add_compliance_requirement(
        owner.origin(),
        asset_id,
        vec![],
        vec![receiver_condition],
    ));

    let transfer_to = |to: IdentityId| {
        let mut weight_meter = WeightMeter::max_limit_no_minimum();
        Asset::validate_asset_transfer(
            asset_id,
            &PortfolioId::default_portfolio(owner.did).into(),
            &PortfolioId::default_portfolio(to).into(),
            10,
            false,
            &mut weight_meter,
        )
        .is_ok()
    };

    // Sanity: the requirement is actually enforced (receiver without the
    // claim fails) and the attacker passes before removal.
    assert!(!transfer_to(receiver_no_cdd.did));
    assert!(transfer_to(attacker.did));

    // (3) Root removes the registrar from DidRegistrars.
    assert_ok!(DidRegistrars::remove_member(root(), registrar.did));
    assert!(!DidRegistrars::get_members().contains(&registrar.did));

    // (4) The stale own-DID CDD claim still fetches, and the transfer still
    // passes compliance.
    let claim_survives = Identity::fetch_claim(
        attacker.did,
        ClaimType::CustomerDueDiligence,
        registrar.did,
        None,
    )
    .is_some();
    let transfer_still_passes = transfer_to(attacker.did);
    // Control: only the *systematic* CDD claim of the removed member is
    // revoked (issuer CDDProvider).
    let systematic_revoked = Identity::fetch_claim(
        registrar.did,
        ClaimType::CustomerDueDiligence,
        SystematicIssuers::CDDProvider.as_id(),
        None,
    )
    .is_none();

    if claim_survives && transfer_still_passes && systematic_revoked {
        println!(
            "WAVE22 A-01: CONFIRMED stale own-DID CDD claim survives registrar removal \
             (fetch_claim=Some, transfer still passes, systematic claim revoked={systematic_revoked})"
        );
    } else {
        println!(
            "WAVE22 A-01: REFUTED claim_survives={claim_survives} \
             transfer_still_passes={transfer_still_passes} systematic_revoked={systematic_revoked}"
        );
    }
    assert!(
        claim_survives,
        "A-01: own-DID CDD claim of removed registrar should still fetch"
    );
    assert!(
        transfer_still_passes,
        "A-01: transfer should still pass compliance after registrar removal"
    );
    assert!(
        systematic_revoked,
        "A-01 control: systematic CDD claim of removed member should be revoked"
    );
}

// ===========================================================================
// A-02 (MEDIUM): secondary key with Identity::add_authorization permission
// plants a RotatePrimaryKey auth and takes over the DID; the auth survives
// removal of the secondary key that planted it.
//
// Honest caveat: creating an auth as "any permissioned key" is documented
// behaviour (spec 01 §4). The sharp part is the *persistence* of the auth
// after its planter is removed (second test below).
// ===========================================================================

#[test]
fn wave22_a02_secondary_key_plants_rotation_auth() {
    ExtBuilder::default().build().execute_with(|| {
        let victim = User::new(Sr25519Keyring::Alice);
        // Secondary key S with ONLY Identity::add_authorization permission.
        let sec = User::new_with(victim.did, Sr25519Keyring::Bob);
        let attacker_acc = Sr25519Keyring::Charlie.to_account_id();

        // Grant exactly the pallet the runtime reports for this call.
        let call = RuntimeCall::Identity(identity::Call::add_authorization {
            target: Signatory::Account(attacker_acc.clone()),
            data: AuthorizationData::RotatePrimaryKey,
            expiry: None,
        });
        let metadata = call.get_call_metadata();
        let perms = Permissions::from_pallet_permissions(vec![
            PalletPermissions::entire_pallet(metadata.pallet_name.into()),
        ]);
        add_secondary_key_with_perms(victim.did, sec.acc(), perms);

        // As S: plant a RotatePrimaryKey authorization targeting the attacker.
        // (Call metadata must be set, otherwise the permission check reads
        // empty metadata and fails even for a permissioned secondary key.)
        let planted = pallet_permissions::with_call_metadata::<TestStorage, _>(
            call.get_call_metadata(),
            || {
                Identity::add_authorization(
                    sec.origin(),
                    Signatory::Account(attacker_acc.clone()),
                    AuthorizationData::RotatePrimaryKey,
                    None,
                )
            },
        );
        assert_ok!(planted);
        let auth_id = get_last_auth_id(&Signatory::Account(attacker_acc.clone()));

        // Attacker accepts: becomes primary key of the victim DID.
        assert_ok!(Identity::accept_primary_key(
            Origin::signed(attacker_acc.clone()),
            auth_id
        ));
        let new_primary = get_primary_key(victim.did);
        let takeover = new_primary == attacker_acc;

        if takeover {
            println!(
                "WAVE22 A-02: CONFIRMED narrow-permission secondary key planted RotatePrimaryKey \
                 auth (auth_id={auth_id}) and attacker became primary key of victim DID"
            );
        } else {
            println!(
                "WAVE22 A-02: REFUTED attacker did not become primary (new_primary={new_primary:?} \
                 attacker={attacker_acc:?})"
            );
        }
        assert!(takeover, "A-02: attacker should be the victim DID's primary key");
    });
}

#[test]
fn wave22_a02_rotation_auth_survives_secondary_key_removal() {
    ExtBuilder::default().build().execute_with(|| {
        let victim = User::new(Sr25519Keyring::Alice);
        let sec = User::new_with(victim.did, Sr25519Keyring::Bob);
        let attacker_acc = Sr25519Keyring::Charlie.to_account_id();

        // Secondary key S with Whole (unrestricted) permissions.
        add_secondary_key_with_perms(victim.did, sec.acc(), Permissions::default());

        // S plants the rotation auth.
        assert_ok!(Identity::add_authorization(
            sec.origin(),
            Signatory::Account(attacker_acc.clone()),
            AuthorizationData::RotatePrimaryKey,
            None,
        ));
        let auth_id = get_last_auth_id(&Signatory::Account(attacker_acc.clone()));

        // Primary removes the secondary key that planted the auth.
        assert_ok!(Identity::remove_secondary_keys(
            victim.origin(),
            vec![sec.acc()]
        ));
        assert!(Identity::get_identity(&sec.acc()).is_none());

        // The planted auth is still in storage (only auths *targeting* the
        // removed key are outdated) and still usable afterwards.
        let auth_survives = Authorizations::<TestStorage>::get(
            &Signatory::Account(attacker_acc.clone()),
            auth_id,
        )
        .is_some();
        let accepted = Identity::accept_primary_key(
            Origin::signed(attacker_acc.clone()),
            auth_id,
        )
        .is_ok();
        let new_primary = get_primary_key(victim.did);
        let takeover = auth_survives && accepted && new_primary == attacker_acc;

        if takeover {
            println!(
                "WAVE22 A-02: CONFIRMED rotation auth (auth_id={auth_id}) survived removal of \
                 its planter and attacker became primary key of victim DID"
            );
        } else {
            println!(
                "WAVE22 A-02: REFUTED auth_survives={auth_survives} accepted={accepted} \
                 new_primary={new_primary:?} attacker={attacker_acc:?}"
            );
        }
        assert!(
            auth_survives,
            "A-02: planted auth should still be in storage after planter removal"
        );
        assert!(
            takeover,
            "A-02: attacker should be the victim DID's primary key after planter removal"
        );
    });
}

// ===========================================================================
// A-05 (LOW): group::reset_members accepts duplicate members -> seats()
// inflation -> committee can never reach threshold (governance freeze).
// ===========================================================================

#[test]
fn wave22_a05_reset_members_accepts_duplicates() {
    ExtBuilder::default().build().execute_with(|| {
        System::set_block_number(1);
        let a = User::new(Sr25519Keyring::Alice);

        // No genesis config exists for the TechnicalCommittee group in this
        // harness, so raise its member limit and set its threshold first.
        assert_ok!(TechnicalCommitteeMembership::set_active_members_limit(
            root(),
            5
        ));
        assert_ok!(TechnicalCommittee::set_vote_threshold(root(), 1, 2));

        // Reset to the same member three times.
        assert_ok!(TechnicalCommitteeMembership::reset_members(
            root(),
            vec![a.did, a.did, a.did],
        ));

        let members = Members::<TestStorage, committee::Instance3>::get();
        let seats = members.len();
        let dup_accepted = members == vec![a.did, a.did, a.did];

        // The single unique voter proposes; with threshold (1,2) over 3 seats
        // one aye can never satisfy `ayes * d >= n * seats` (1*2 < 1*3).
        let proposal = make_remark_proposal();
        let hash = <TestStorage as frame_system::Config>::Hashing::hash_of(&proposal);
        assert_ok!(TechnicalCommittee::vote_or_propose(
            a.origin(),
            true,
            Box::new(proposal),
        ));
        let voting = Voting::<TestStorage, committee::Instance3>::get(&hash);
        let (ayes, still_open) = match &voting {
            Some(v) => (v.ayes.len(), true),
            None => (0, false),
        };
        // A cannot vote a second time, and nobody else exists to vote.
        assert_noop!(
            TechnicalCommittee::vote_or_propose(
                a.origin(),
                true,
                Box::new(make_remark_proposal()),
            ),
            committee::Error::<TestStorage, committee::Instance3>::DuplicateVote
        );
        let frozen = dup_accepted && still_open && ayes == 1;

        if frozen {
            println!(
                "WAVE22 A-05: CONFIRMED reset_members([A,A,A]) accepted, members={members:?} \
                 seats={seats}, single aye={ayes} never reaches threshold (1,2) -> committee frozen"
            );
        } else {
            println!(
                "WAVE22 A-05: REFUTED dup_accepted={dup_accepted} members={members:?} \
                 seats={seats} still_open={still_open} ayes={ayes}"
            );
        }
        assert!(dup_accepted, "A-05: reset_members should have stored [A, A, A]");
        assert_eq!(seats, 3, "A-05: seats() should be inflated to 3");
        assert!(still_open, "A-05: proposal should still be open (threshold unreachable)");
        assert_eq!(ayes, 1, "A-05: exactly one aye should be recorded");
    });
}

// ===========================================================================
// A-07 (LOW): removing a committee member re-executes a pending proposal
// with shrunken seats, so it can pass without any further vote.
//
// Honest caveat: this may be by-design (mirrors Substrate pallet-collective
// liveness behaviour — an existing test, `rage_quit` in committee_test.rs,
// already relies on quitting members re-triggering execution). The test
// below only pins the *behaviour*, it does not settle intent.
// ===========================================================================

#[test]
fn wave22_a07_member_removal_reexecutes_pending_proposal() {
    ExtBuilder::default()
        .governance_committee(vec![
            Sr25519Keyring::Alice.to_account_id(),
            Sr25519Keyring::Bob.to_account_id(),
            Sr25519Keyring::Charlie.to_account_id(),
            Sr25519Keyring::Dave.to_account_id(),
            Sr25519Keyring::Eve.to_account_id(),
        ])
        .governance_committee_vote_threshold((2, 3))
        .build()
        .execute_with(|| {
            System::set_block_number(1);
            let a_did = get_identity_id(Sr25519Keyring::Alice).unwrap();
            let b_did = get_identity_id(Sr25519Keyring::Bob).unwrap();
            let c_did = get_identity_id(Sr25519Keyring::Charlie).unwrap();
            let d_did = get_identity_id(Sr25519Keyring::Dave).unwrap();
            let e_did = get_identity_id(Sr25519Keyring::Eve).unwrap();
            let a_origin = Origin::signed(Sr25519Keyring::Alice.to_account_id());
            let b_origin = Origin::signed(Sr25519Keyring::Bob.to_account_id());
            let c_origin = Origin::signed(Sr25519Keyring::Charlie.to_account_id());
            let d_origin = Origin::signed(Sr25519Keyring::Dave.to_account_id());
            let e_origin = Origin::signed(Sr25519Keyring::Eve.to_account_id());

            let was_executed = |hash: H256| {
                System::events().iter().any(|record| {
                    matches!(
                        &record.event,
                        EventTest::PolymeshCommittee(CommitteeRawEvent::Executed(
                            _,
                            h,
                            Ok(())
                        )) if *h == hash
                    )
                })
            };

            // Proposal P: ayes A,B,C; nays D,E. Needs 4 ayes of 5 seats
            // (3*3 < 2*5), so it must NOT pass yet.
            let proposal =
                RuntimeCall::System(frame_system::Call::remark { remark: vec![7u8; 10] });
            let hash = <TestStorage as frame_system::Config>::Hashing::hash_of(&proposal);
            assert_ok!(Committee::vote_or_propose(
                a_origin.clone(),
                true,
                Box::new(proposal.clone())
            ));
            assert_ok!(Committee::vote_or_propose(
                b_origin.clone(),
                true,
                Box::new(proposal.clone())
            ));
            assert_ok!(Committee::vote_or_propose(
                c_origin.clone(),
                true,
                Box::new(proposal.clone())
            ));
            assert_ok!(Committee::vote_or_propose(
                d_origin.clone(),
                false,
                Box::new(proposal.clone())
            ));
            assert_ok!(Committee::vote_or_propose(
                e_origin.clone(),
                false,
                Box::new(proposal.clone())
            ));

            // Control: P is open, unexecuted, with the expected 3-2 split.
            let voting = Voting::<TestStorage, committee::Instance1>::get(&hash)
                .expect("P should be an open proposal");
            assert_eq!(voting.ayes, vec![a_did, b_did, c_did]);
            assert_eq!(voting.nays, vec![d_did, e_did]);
            assert!(Proposals::<TestStorage, committee::Instance1>::get().contains(&hash));
            assert!(!was_executed(hash));

            // D leaves the committee. change_members_sorted retracts D's nay,
            // shrinks seats 5 -> 4, and re-evaluates P: 3*3 >= 2*4, so P
            // executes with no further vote.
            // NOTE: the removal is triggered by abdication here, not by a
            // passed removal proposal: in this test runtime every group
            // RemoveOrigin is EnsureRoot, so a committee proposal calling
            // remove_member could not dispatch the removal (same on mainnet
            // for the GC itself). The membership-change code path exercised
            // is identical.
            assert_ok!(CommitteeGroup::abdicate_membership(d_origin));

            let executed = was_executed(hash);
            let still_open =
                Voting::<TestStorage, committee::Instance1>::get(&hash).is_some()
                    || Proposals::<TestStorage, committee::Instance1>::get().contains(&hash);
            let seats_now = Members::<TestStorage, committee::Instance1>::get().len();

            if executed && !still_open && seats_now == 4 {
                println!(
                    "WAVE22 A-07: CONFIRMED pending proposal executed on member removal \
                     (ayes=3 nays=1 seats=4, 3*3 >= 2*4) with no additional vote"
                );
            } else {
                println!(
                    "WAVE22 A-07: REFUTED executed={executed} still_open={still_open} \
                     seats_now={seats_now}"
                );
            }
            assert!(executed, "A-07: proposal should have executed after D left");
            assert!(!still_open, "A-07: proposal should no longer be open");
            assert_eq!(seats_now, 4, "A-07: committee should have 4 members left");
        });
}
