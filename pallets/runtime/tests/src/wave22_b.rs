//! Wave 22 verification tests — Area B (settlement / STO).
//!
//! Verdict semantics: each `#[test]` asserts the buggy behaviour claimed by
//! hunter B (see `hunter-b/FINDINGS.md`, items B-01 and B-02).
//! PASS = bug CONFIRMED; FAIL = bug REFUTED. Every test first computes the
//! observed values, prints a `WAVE22 <ID>: CONFIRMED / REFUTED ...` line with
//! them, and only then asserts — so the verdict is readable in the CI log
//! even when the test itself fails.
//!
//! FRAME-level note (CORRECTED — the first draft of this file had it
//! backwards): a dispatchable that returns `Err` DOES roll its storage
//! changes back, because dispatch through `RuntimeCall` runs inside a
//! storage transaction. Proof in-repo: `approve_max_weight_too_low_charges_decode_cost`
//! (`multisig.rs`) dispatches an `approve` with too-low `max_weight` via
//! `RuntimeCall`, gets `MaxWeightTooLow`, and asserts the vote was rolled
//! back and the proposal is still `Active` — the `Proposals::take` inside
//! `execute_proposal` did not survive the error. (The `sp-runtime`
//! `DispatchOutcome` wording about failed dispatches "still persisting"
//! concerns extrinsic inclusion/validity, not the storage effects of a
//! dispatchable — and the multisig test above is behavioural proof in this
//! very runtime.) Consequence for B-01: `simplified_asset_transfer` has no
//! explicit `with_transaction`, but it does not need one — the dispatch-level
//! transaction of `execute_manual_instruction` already makes the locked
//! execution atomic. A failing leg therefore rolls the whole execution
//! back: no partial settlement, no permanent strand. The B-01 tests below
//! dispatch the execution through `RuntimeCall` (never a direct pallet-fn
//! call, which would bypass the transaction and show a false CONFIRMED)
//! and assert the claimed partial settlement — they are expected to print
//! REFUTED.

use frame_support::assert_ok;
use sp_keyring::Sr25519Keyring;
use sp_runtime::traits::Dispatchable;
use sp_std::collections::btree_set::BTreeSet;

use pallet_asset::BalanceOf;
use pallet_nft::{NumberOfNFTs, Owner};
use pallet_portfolio::{PortfolioAssetBalances, PortfolioLockedAssets, PortfolioNFT};
use pallet_settlement::{
    Error as SettlementError, InstructionLegs, InstructionStatuses, LockedTimestamp,
    VenueCounter,
};
use pallet_sto::Event as StoEvent;
use pallet_sto::{FundraiserCount, FundraiserName, Fundraisers, FundingMethod, PriceTier};
use polymesh_primitives::asset::AssetId;
use polymesh_primitives::settlement::{
    InstructionId, InstructionStatus, Leg, SettlementType, VenueDetails, VenueId, VenueType,
};
use polymesh_primitives::{
    IdentityId, NFTId, NFTs, PortfolioId, PortfolioKind, PortfolioName, PortfolioNumber,
    WeightMeter,
};
use polymesh_runtime_common::Weight;

use crate::asset_pallet::setup::create_and_issue_sample_asset;
use crate::settlement_pallet::setup::{
    add_and_affirm_simple_instruction, create_and_issue_sample_asset_with_venue,
};
use crate::storage::{make_account_with_portfolio, EventTest, RuntimeCall, User};
use crate::{ExtBuilder, TestStorage};

type RuntimeOrigin = <TestStorage as frame_system::Config>::RuntimeOrigin;

type Asset = pallet_asset::Pallet<TestStorage>;
type Nft = pallet_nft::Pallet<TestStorage>;
type Portfolio = pallet_portfolio::Pallet<TestStorage>;
type Settlement = pallet_settlement::Pallet<TestStorage>;
type Sto = pallet_sto::Pallet<TestStorage>;
type System = frame_system::Pallet<TestStorage>;
type Timestamp = pallet_timestamp::Pallet<TestStorage>;

// ===========================================================================
// B-01 (HIGH): locked-instruction execution is NOT atomic.
// CLAIM: `simplified_asset_transfer` (pallets/settlement/src/lib.rs:3542)
// iterates legs one by one and calls `simplified_fungible_transfer` /
// `simplified_nft_transfer` with `?` and no `with_transaction` /
// `#[require_transactional]`, unlike the normal path (`execute_instruction`
// :2038, wrapped in `with_transaction` at :2065). If leg N fails, legs
// 1..N-1 have already moved, the locks were already released
// (`release_locks` runs before the leg loop), the instruction is NOT pruned
// and its status stays `LockedForExecution`.
//
// REFUTATION (settled from repo evidence, see the file header): the claim
// ignores the dispatch-level storage transaction. A dispatchable that
// returns `Err` rolls its storage changes back — proven by the repo's own
// `approve_max_weight_too_low_charges_decode_cost` multisig test. So a
// failing leg rolls the whole locked execution back: nothing moves, the
// locks stay held, the instruction stays `LockedForExecution`, and a
// `reject` just marks it `Rejected` with nothing moved. The B-01 tests
// therefore dispatch the execution through `RuntimeCall` (the on-chain
// path) and assert the claimed partial settlement — they are expected to
// print REFUTED. (A direct pallet-fn call would bypass the transaction
// and show a false CONFIRMED; that is exactly the trap the first draft
// of this file fell into.)
//
// NOT part of this finding (documented working-as-intended, spec 10 §6):
// the `simplified_*` transfers skipping compliance / asset-freeze checks.
// This finding is purely about atomicity, which is not documented anywhere
// in spec §6.
// ===========================================================================

// Dispatch helper: `execute_manual_instruction` as a real extrinsic, so the
// dispatch-level storage transaction applies (a failing execution must roll
// back, exactly as on-chain).
fn dispatch_execute_manual_instruction(
    origin: RuntimeOrigin,
    fungible_transfers: u32,
    nfts_transfers: u32,
) -> frame_support::dispatch::DispatchResultWithPostInfo {
    RuntimeCall::Settlement(pallet_settlement::Call::execute_manual_instruction {
        id: InstructionId(0),
        asset_holder: None,
        fungible_transfers,
        nfts_transfers,
        offchain_transfers: 0,
        weight_limit: None,
    })
    .dispatch(origin)
}

/// B-01, trigger 1 (cleanest): the receiver deletes the still-empty user
/// portfolio that leg 1 pays into, after the lock and before execution.
/// Leg 0 (fungible Alice -> Bob default portfolio) would succeed; leg 1
/// (fungible Alice -> Bob user portfolio) fails in
/// `ensure_portfolio_validity`. Claimed buggy outcome: leg 0 has moved,
/// leg 1 has not, the instruction is still `LockedForExecution` with its
/// locks released, and no recovery path (retry / re-lock / reject)
/// reverses leg 0. EXPECTED: REFUTED — the dispatch-level transaction
/// rolls the whole execution back (see file header).
#[test]
fn b01_locked_execution_partial_settlement_via_deleted_receiver_portfolio() {
    ExtBuilder::default().build().execute_with(|| {
        let alice = User::new(Sr25519Keyring::Alice);
        let bob = User::new(Sr25519Keyring::Bob);
        let dave = User::new(Sr25519Keyring::Dave);
        let alice_default = PortfolioId::default_portfolio(alice.did);
        let bob_default = PortfolioId::default_portfolio(bob.did);
        let bob_user =
            PortfolioId::new(bob.did, PortfolioKind::User(PortfolioNumber(1)));

        // Dave (mediator) creates/issues the asset and funds Alice with 1_500.
        let (asset_id, venue_id) = create_and_issue_sample_asset_with_venue(&dave);
        assert_ok!(Asset::simplified_fungible_transfer(
            asset_id,
            PortfolioId::default_portfolio(dave.did).into(),
            alice_default.clone().into(),
            1_500,
            InstructionId(0),
            None,
            dave.did,
            &mut WeightMeter::max_limit_no_minimum(),
        ));

        // Bob creates the user portfolio that will receive leg 1.
        assert_ok!(Portfolio::create_portfolio(
            bob.origin(),
            PortfolioName(b"Recv".into())
        ));

        // 2-leg SettleAfterLock instruction, both legs from Alice.
        let legs = vec![
            Leg::Fungible {
                sender: alice_default.clone().into(),
                receiver: bob_default.clone().into(),
                asset_id,
                amount: 1_000,
            },
            Leg::Fungible {
                sender: alice_default.clone().into(),
                receiver: bob_user.clone().into(),
                asset_id,
                amount: 500,
            },
        ];
        assert_ok!(Settlement::add_instruction_with_mediators(
            dave.origin(),
            venue_id,
            SettlementType::SettleAfterLock,
            None,
            None,
            legs,
            None,
            BTreeSet::from([dave.did]).try_into().unwrap(),
        ));
        assert_ok!(Settlement::affirm_instruction(
            alice.origin(),
            InstructionId(0),
            BTreeSet::from([alice_default.clone().into()])
                .try_into()
                .unwrap(),
        ));
        assert_ok!(Settlement::affirm_instruction_as_mediator(
            dave.origin(),
            InstructionId(0),
            Some(Timestamp::get() + 1),
        ));

        System::set_block_number(1);
        assert_ok!(Settlement::lock_instruction(
            dave.origin(),
            InstructionId(0),
            Weight::MAX
        ));
        assert_eq!(
            InstructionStatuses::<TestStorage>::get(InstructionId(0)),
            InstructionStatus::LockedForExecution
        );

        // State change between lock and execution: Bob deletes the still-empty
        // receiver portfolio (allowed: PortfolioAssetCount == 0, no NFTs).
        assert_ok!(Portfolio::delete_portfolio(
            bob.origin(),
            PortfolioNumber(1)
        ));

        // Mediator executes the locked instruction, dispatched as a real
        // extrinsic (RuntimeCall) so the dispatch-level storage transaction
        // applies: on leg-1 failure the whole execution must roll back.
        let exec_res = dispatch_execute_manual_instruction(dave.origin(), 2, 0);
        let exec_err = exec_res.as_ref().err().map(|e| format!("{:?}", e.error));

        // Observations after the failed execution.
        let bob_did_balance = BalanceOf::<TestStorage>::get(&asset_id, &bob.did);
        let alice_did_balance = BalanceOf::<TestStorage>::get(&asset_id, &alice.did);
        let bob_default_balance =
            PortfolioAssetBalances::<TestStorage>::get(&bob_default, &asset_id);
        let alice_portfolio_balance =
            PortfolioAssetBalances::<TestStorage>::get(&alice_default, &asset_id);
        let status = InstructionStatuses::<TestStorage>::get(InstructionId(0));
        let legs_left =
            InstructionLegs::<TestStorage>::iter_prefix_values(InstructionId(0)).count();
        let locks_left =
            PortfolioLockedAssets::<TestStorage>::get(&alice_default, asset_id);
        let lock_ts_still_set =
            LockedTimestamp::<TestStorage>::get(InstructionId(0)).is_some();

        // No recovery: retry fails, re-lock fails, reject does not reverse leg 0.
        // (Retry is also dispatched as a real extrinsic; a direct pallet-fn
        // call here would bypass the transaction and could partially move
        // leg 0 before failing, corrupting the post-reject observations.)
        let retry_res = dispatch_execute_manual_instruction(dave.origin(), 2, 0);
        let relock_res =
            Settlement::lock_instruction(dave.origin(), InstructionId(0), Weight::MAX);
        let relock_is_already_locked = matches!(
            &relock_res,
            Err(e) if e.error == SettlementError::<TestStorage>::InstructionAlreadyLocked.into()
        );
        assert_ok!(Settlement::reject_instruction_as_mediator(
            dave.origin(),
            InstructionId(0),
            None
        ));
        let status_after_reject =
            InstructionStatuses::<TestStorage>::get(InstructionId(0));
        let bob_balance_after_reject = BalanceOf::<TestStorage>::get(&asset_id, &bob.did);

        let confirmed = exec_res.is_err()
            && bob_did_balance == 1_000
            && alice_did_balance == 500
            && bob_default_balance == 1_000
            && alice_portfolio_balance == 500
            && status == InstructionStatus::LockedForExecution
            && legs_left == 2
            && locks_left == 0
            && lock_ts_still_set
            && retry_res.is_err()
            && relock_is_already_locked
            && matches!(status_after_reject, InstructionStatus::Rejected(_))
            && bob_balance_after_reject == 1_000;
        // What actually happens (dispatch-level transaction): the failed
        // execution rolls back cleanly — nothing moved, locks still held.
        let rolled_back_cleanly = exec_res.is_err()
            && bob_did_balance == 0
            && alice_did_balance == 1_500
            && bob_default_balance == 0
            && alice_portfolio_balance == 1_500
            && status == InstructionStatus::LockedForExecution
            && legs_left == 2
            && locks_left == 1_500
            && lock_ts_still_set
            && retry_res.is_err()
            && relock_is_already_locked
            && matches!(status_after_reject, InstructionStatus::Rejected(_))
            && bob_balance_after_reject == 0;
        println!(
            "WAVE22 B-01 (deleted receiver portfolio): rolled_back_cleanly={} (expected true: dispatch transaction undoes the failed execution)",
            rolled_back_cleanly
        );
        println!(
            "WAVE22 B-01 (deleted receiver portfolio): {} | exec_err={:?} bob_did={} alice_did={} bob_default_pf={} alice_pf={} status={:?} legs_left={} locks_left={} lock_ts_set={} retry_err={} relock_already_locked={} status_after_reject={:?} bob_after_reject={}",
            if confirmed { "CONFIRMED" } else { "REFUTED" },
            exec_err,
            bob_did_balance,
            alice_did_balance,
            bob_default_balance,
            alice_portfolio_balance,
            status,
            legs_left,
            locks_left,
            lock_ts_still_set,
            retry_res.is_err(),
            relock_is_already_locked,
            status_after_reject,
            bob_balance_after_reject,
        );
        assert!(
            confirmed,
            "WAVE22 B-01: expected partial settlement (leg 0 moved, leg 1 failed, still LockedForExecution, unrecoverable)"
        );
    });
}

/// B-01, trigger 2: the issuer freezes the sender's NFT after the lock.
/// Leg 0 (fungible Alice -> Bob) would succeed; leg 1 (NFT Alice -> Bob)
/// fails in `ensure_sender_owns_nfts` (`InvalidNFTTransferNFTIsFrozen`).
/// Claimed buggy outcome (same as trigger 1): half-settled, still locked,
/// no recovery path reverses leg 0. EXPECTED: REFUTED — the dispatch-level
/// transaction rolls the whole execution back (see file header).
#[test]
fn b01_locked_execution_partial_settlement_via_frozen_nft() {
    ExtBuilder::default().build().execute_with(|| {
        let alice = User::new(Sr25519Keyring::Alice);
        let bob = User::new(Sr25519Keyring::Bob);
        let dave = User::new(Sr25519Keyring::Dave);
        let alice_default = PortfolioId::default_portfolio(alice.did);
        let bob_default = PortfolioId::default_portfolio(bob.did);

        // 2-leg instruction: 1_000 fungible Alice -> Bob, NFT #1 Alice -> Bob.
        // Dave (mediator) created/issued both assets, so he can freeze the NFT.
        let (asset_id, nft_asset_id) = add_and_affirm_simple_instruction(
            alice,
            bob,
            dave,
            SettlementType::SettleAfterLock,
        );

        System::set_block_number(1);
        assert_ok!(Settlement::lock_instruction(
            dave.origin(),
            InstructionId(0),
            Weight::MAX
        ));
        assert_eq!(
            InstructionStatuses::<TestStorage>::get(InstructionId(0)),
            InstructionStatus::LockedForExecution
        );

        // State change between lock and execution: issuer freezes Alice's NFT.
        assert_ok!(Nft::set_nfts_frozen(
            dave.origin(),
            alice_default.clone().into(),
            NFTs::new_unverified(nft_asset_id, vec![NFTId(1)]),
            true,
        ));

        // Mediator executes the locked instruction, dispatched as a real
        // extrinsic (RuntimeCall) so the dispatch-level storage transaction
        // applies: on leg-1 (NFT) failure the whole execution must roll back.
        let exec_res = dispatch_execute_manual_instruction(dave.origin(), 1, 1);
        let exec_err = exec_res.as_ref().err().map(|e| format!("{:?}", e.error));

        // Observations after the failed execution.
        let bob_fungible = BalanceOf::<TestStorage>::get(&asset_id, &bob.did);
        let alice_fungible = BalanceOf::<TestStorage>::get(&asset_id, &alice.did);
        let bob_nfts = NumberOfNFTs::<TestStorage>::get(&nft_asset_id, bob.did);
        let alice_nfts = NumberOfNFTs::<TestStorage>::get(&nft_asset_id, alice.did);
        let nft_owner = Owner::<TestStorage>::get(nft_asset_id, NFTId(1));
        let nft_still_in_alice_pf =
            PortfolioNFT::<TestStorage>::get((&alice_default, &nft_asset_id, NFTId(1)));
        let status = InstructionStatuses::<TestStorage>::get(InstructionId(0));
        let legs_left =
            InstructionLegs::<TestStorage>::iter_prefix_values(InstructionId(0)).count();

        // No recovery: retry fails, re-lock fails, reject does not reverse leg 0.
        // (Retry also dispatched as a real extrinsic, same reason as trigger 1.)
        let retry_res = dispatch_execute_manual_instruction(dave.origin(), 1, 1);
        let relock_res =
            Settlement::lock_instruction(dave.origin(), InstructionId(0), Weight::MAX);
        let relock_is_already_locked = matches!(
            &relock_res,
            Err(e) if e.error == SettlementError::<TestStorage>::InstructionAlreadyLocked.into()
        );
        assert_ok!(Settlement::reject_instruction_as_mediator(
            dave.origin(),
            InstructionId(0),
            None
        ));
        let status_after_reject =
            InstructionStatuses::<TestStorage>::get(InstructionId(0));
        let bob_fungible_after_reject = BalanceOf::<TestStorage>::get(&asset_id, &bob.did);
        let nft_owner_after_reject = Owner::<TestStorage>::get(nft_asset_id, NFTId(1));

        let confirmed = exec_res.is_err()
            && bob_fungible == 1_000
            && alice_fungible == 0
            && bob_nfts == 0
            && alice_nfts == 1
            && nft_owner == Some(alice_default.clone().into())
            && nft_still_in_alice_pf
            && status == InstructionStatus::LockedForExecution
            && legs_left == 2
            && retry_res.is_err()
            && relock_is_already_locked
            && matches!(status_after_reject, InstructionStatus::Rejected(_))
            && bob_fungible_after_reject == 1_000
            && nft_owner_after_reject == Some(alice_default.clone().into());
        // What actually happens (dispatch-level transaction): the failed
        // execution rolls back cleanly — fungible leg never moved either.
        let rolled_back_cleanly = exec_res.is_err()
            && bob_fungible == 0
            && alice_fungible == 1_000
            && bob_nfts == 0
            && alice_nfts == 1
            && nft_owner == Some(alice_default.clone().into())
            && nft_still_in_alice_pf
            && status == InstructionStatus::LockedForExecution
            && legs_left == 2
            && retry_res.is_err()
            && relock_is_already_locked
            && matches!(status_after_reject, InstructionStatus::Rejected(_))
            && bob_fungible_after_reject == 0
            && nft_owner_after_reject == Some(alice_default.clone().into());
        println!(
            "WAVE22 B-01 (frozen NFT): rolled_back_cleanly={} (expected true: dispatch transaction undoes the failed execution)",
            rolled_back_cleanly
        );
        println!(
            "WAVE22 B-01 (frozen NFT): {} | exec_err={:?} bob_fungible={} alice_fungible={} bob_nfts={} alice_nfts={} nft_owner={:?} nft_in_alice_pf={} status={:?} legs_left={} retry_err={} relock_already_locked={} status_after_reject={:?} bob_after_reject={} nft_owner_after_reject={:?}",
            if confirmed { "CONFIRMED" } else { "REFUTED" },
            exec_err,
            bob_fungible,
            alice_fungible,
            bob_nfts,
            alice_nfts,
            nft_owner,
            nft_still_in_alice_pf,
            status,
            legs_left,
            retry_res.is_err(),
            relock_is_already_locked,
            status_after_reject,
            bob_fungible_after_reject,
            nft_owner_after_reject,
        );
        assert!(
            confirmed,
            "WAVE22 B-01: expected partial settlement (fungible leg moved, NFT leg failed, still LockedForExecution, unrecoverable)"
        );
    });
}

// ===========================================================================
// B-02 (MEDIUM): STO `invest` rounds the cost DOWN per call.
// `base_invest` (pallets/sto/src/lib.rs:859) computes the per-tier cost as
// `purchase_amount_in_tier * tier.price / 1_000_000` with integer division
// PER `invest` CALL (:905-:935). Splitting a purchase into many 1-token
// calls discards the fractional remainder every time, so the split buyer
// pays less than the bulk buyer for the same number of tokens.
// `create_fundraiser` (:482) only validates tier totals > 0 (:518-:525);
// there is no `price > 0` validation and no minimum price.
// Honest note: mitigation is in the issuer's hands (high
// `minimum_investment`, prices that are whole multiples of 1_000_000), so
// real-world impact depends on the fundraiser's configuration.
// ===========================================================================

/// Shared STO setup: Alice issues an offering asset and a raising asset,
/// funds Bob and Charlie with 1_000_000 raising asset each, and creates a
/// `VenueType::Sto` venue.
struct B02Setup {
    alice: User,
    alice_portfolio: PortfolioId,
    bob: User,
    bob_portfolio: PortfolioId,
    charlie: User,
    charlie_portfolio: PortfolioId,
    offering_asset: AssetId,
    raise_asset: AssetId,
    venue_id: VenueId,
}

fn b02_setup() -> B02Setup {
    let (alice, alice_portfolio) = make_account_with_portfolio(Sr25519Keyring::Alice);
    let (bob, bob_portfolio) = make_account_with_portfolio(Sr25519Keyring::Bob);
    let (charlie, charlie_portfolio) =
        make_account_with_portfolio(Sr25519Keyring::Charlie);

    let offering_asset = create_and_issue_sample_asset(&alice);
    let raise_asset = create_and_issue_sample_asset(&alice);

    let mut weight_meter = WeightMeter::max_limit_no_minimum();
    assert_ok!(Asset::unverified_transfer_asset(
        alice_portfolio.clone().into(),
        bob_portfolio.clone().into(),
        raise_asset,
        1_000_000,
        None,
        None,
        IdentityId::default(),
        false,
        &mut weight_meter
    ));
    assert_ok!(Asset::unverified_transfer_asset(
        alice_portfolio.clone().into(),
        charlie_portfolio.clone().into(),
        raise_asset,
        1_000_000,
        None,
        None,
        IdentityId::default(),
        false,
        &mut weight_meter
    ));

    let venue_id = VenueCounter::<TestStorage>::get();
    assert_ok!(Settlement::create_venue(
        alice.origin(),
        VenueDetails::default(),
        BTreeSet::from([Sr25519Keyring::Alice.to_account_id()]),
        VenueType::Sto
    ));

    B02Setup {
        alice,
        alice_portfolio,
        bob,
        bob_portfolio,
        charlie,
        charlie_portfolio,
        offering_asset,
        raise_asset,
        venue_id,
    }
}

/// B-02: one tier, price 1_500_000 (= 1.5 raising units per token),
/// `minimum_investment = 0`. Bulk buy of 100 tokens costs
/// 100 * 1_500_000 / 1_000_000 = 150; 100 buys of 1 token cost
/// 100 * (1 * 1_500_000 / 1_000_000) = 100 * 1 = 100. Same 100 tokens,
/// 50 units (33.3%) cheaper when split.
#[test]
fn b02_split_purchase_underpays_vs_bulk() {
    ExtBuilder::default()
        .did_registrars(vec![Sr25519Keyring::Eve.to_account_id()])
        .build()
        .execute_with(|| {
            let B02Setup {
                alice,
                alice_portfolio,
                bob,
                bob_portfolio,
                charlie,
                charlie_portfolio,
                offering_asset,
                raise_asset,
                venue_id,
            } = b02_setup();

            // Two identical fundraisers on the same offering asset.
            let fundraiser_bulk = FundraiserCount::<TestStorage>::get(offering_asset);
            assert_ok!(Sto::create_fundraiser(
                alice.origin(),
                alice_portfolio.clone(),
                offering_asset,
                alice_portfolio.clone(),
                raise_asset,
                vec![PriceTier {
                    total: 100,
                    price: 1_500_000
                }],
                venue_id,
                None,
                None,
                0,
                FundraiserName::default(),
            ));
            let fundraiser_split = FundraiserCount::<TestStorage>::get(offering_asset);
            assert_ok!(Sto::create_fundraiser(
                alice.origin(),
                alice_portfolio.clone(),
                offering_asset,
                alice_portfolio.clone(),
                raise_asset,
                vec![PriceTier {
                    total: 100,
                    price: 1_500_000
                }],
                venue_id,
                None,
                None,
                0,
                FundraiserName::default(),
            ));

            let bob_raise_before = BalanceOf::<TestStorage>::get(&raise_asset, &bob.did);
            let bob_offering_before =
                BalanceOf::<TestStorage>::get(&offering_asset, &bob.did);
            let charlie_raise_before =
                BalanceOf::<TestStorage>::get(&raise_asset, &charlie.did);
            let charlie_offering_before =
                BalanceOf::<TestStorage>::get(&offering_asset, &charlie.did);

            // Bob: 100 tokens in one call.
            assert_ok!(Sto::invest(
                bob.origin(),
                offering_asset,
                fundraiser_bulk,
                bob_portfolio.clone(),
                FundingMethod::OnChain(bob_portfolio.clone()),
                100,
                Some(1_500_000),
            ));

            // Charlie: 1 token x 100 calls.
            for _ in 0..100 {
                assert_ok!(Sto::invest(
                    charlie.origin(),
                    offering_asset,
                    fundraiser_split,
                    charlie_portfolio.clone(),
                    FundingMethod::OnChain(charlie_portfolio.clone()),
                    1,
                    Some(1_500_000),
                ));
            }

            // Observations: balances + tier remaining + Invested event totals.
            let bob_paid =
                bob_raise_before - BalanceOf::<TestStorage>::get(&raise_asset, &bob.did);
            let bob_got = BalanceOf::<TestStorage>::get(&offering_asset, &bob.did)
                - bob_offering_before;
            let charlie_paid = charlie_raise_before
                - BalanceOf::<TestStorage>::get(&raise_asset, &charlie.did);
            let charlie_got =
                BalanceOf::<TestStorage>::get(&offering_asset, &charlie.did)
                    - charlie_offering_before;
            let bulk_remaining = Fundraisers::<TestStorage>::get(offering_asset, fundraiser_bulk)
                .unwrap()
                .tiers[0]
                .remaining;
            let split_remaining =
                Fundraisers::<TestStorage>::get(offering_asset, fundraiser_split)
                    .unwrap()
                    .tiers[0]
                    .remaining;

            let mut bulk_event_raise = 0u128;
            let mut split_event_raise = 0u128;
            for record in System::events() {
                if let EventTest::Sto(StoEvent::Invested {
                    fundraiser_id,
                    raise_amount,
                    ..
                }) = record.event
                {
                    if fundraiser_id == fundraiser_bulk {
                        bulk_event_raise += raise_amount;
                    } else if fundraiser_id == fundraiser_split {
                        split_event_raise += raise_amount;
                    }
                }
            }

            let confirmed = bob_paid == 150
                && charlie_paid == 100
                && bob_got == 100
                && charlie_got == 100
                && bulk_remaining == 0
                && split_remaining == 0
                && bulk_event_raise == 150
                && split_event_raise == 100;
            println!(
                "WAVE22 B-02 (split vs bulk): {} | bulk_paid={} (event {}) split_paid={} (event {}) bob_got={} charlie_got={} bulk_remaining={} split_remaining={} underpayment={} ({:.1}%)",
                if confirmed { "CONFIRMED" } else { "REFUTED" },
                bob_paid,
                bulk_event_raise,
                charlie_paid,
                split_event_raise,
                bob_got,
                charlie_got,
                bulk_remaining,
                split_remaining,
                bob_paid.saturating_sub(charlie_paid),
                100.0 * (bob_paid.saturating_sub(charlie_paid)) as f64 / bob_paid as f64,
            );
            assert!(
                confirmed,
                "WAVE22 B-02: expected bulk 150 vs split 100 paid for the same 100 tokens"
            );
        });
}

/// B-02, lower bound: price 500_000 (< 1_000_000) with a 1-token purchase
/// gives cost 0, so the raising-asset leg has amount 0 and the invest must
/// fail in `ensure_valid_fungible_leg` (`ZeroAmount`,
/// pallets/settlement/src/lib.rs:2981). A fully free mint is NOT possible
/// through this path — only a systematic discount (see the test above).
#[test]
fn b02_sub_unit_price_single_token_costs_zero() {
    ExtBuilder::default()
        .did_registrars(vec![Sr25519Keyring::Eve.to_account_id()])
        .build()
        .execute_with(|| {
            let B02Setup {
                alice,
                alice_portfolio,
                bob,
                bob_portfolio,
                charlie: _charlie,
                charlie_portfolio: _charlie_portfolio,
                offering_asset,
                raise_asset,
                venue_id,
            } = b02_setup();

            let fundraiser_id = FundraiserCount::<TestStorage>::get(offering_asset);
            assert_ok!(Sto::create_fundraiser(
                alice.origin(),
                alice_portfolio.clone(),
                offering_asset,
                alice_portfolio.clone(),
                raise_asset,
                vec![PriceTier {
                    total: 100,
                    price: 500_000
                }],
                venue_id,
                None,
                None,
                0,
                FundraiserName::default(),
            ));

            let res = Sto::invest(
                bob.origin(),
                offering_asset,
                fundraiser_id,
                bob_portfolio.clone(),
                FundingMethod::OnChain(bob_portfolio.clone()),
                1,
                None,
            );
            let err = res.as_ref().err().map(|e| format!("{:?}", e));
            // The failure must be the settlement leg validation, not some
            // earlier check (e.g. minimum investment or venue).
            let err_is_zero_amount = matches!(
                &res,
                Err(e) if *e == SettlementError::<TestStorage>::ZeroAmount.into()
            );
            let remaining = Fundraisers::<TestStorage>::get(offering_asset, fundraiser_id)
                .unwrap()
                .tiers[0]
                .remaining;

            let confirmed = res.is_err() && err_is_zero_amount && remaining == 100;
            println!(
                "WAVE22 B-02 (sub-unit price): {} | invest_err={:?} err_is_zero_amount={} tiers_remaining={}",
                if confirmed { "CONFIRMED" } else { "REFUTED" },
                err,
                err_is_zero_amount,
                remaining,
            );
            assert!(
                confirmed,
                "WAVE22 B-02: expected 1-token invest at price 500_000 to fail with settlement ZeroAmount and leave the tier untouched"
            );
        });
}
