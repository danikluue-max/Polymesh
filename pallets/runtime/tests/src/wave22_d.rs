// Wave 22 — Polymesh verification tests, AREA D
// (relayer / multisig / protocol-fee / precompiles).
//
// Harness: crate `polymesh-runtime-tests` (`pallets/runtime/tests/`).
// Run in CI with:
//   SKIP_WASM_BUILD=1 cargo test -p polymesh-runtime-tests wave22_d
// This file needs `mod wave22_d;` added to `pallets/runtime/tests/src/lib.rs`
// (do NOT edit the repo's lib.rs here — the CI staging applies that one line).
//
// Verdict semantics: every `#[test]` below asserts the buggy behaviour claimed
// by hunter D. PASS = bug CONFIRMED; FAIL = bug REFUTED. Each test also prints
// `WAVE22 <ID>: CONFIRMED|REFUTED ...` with the observed values, so the verdict
// is readable in the CI log even when the test itself fails.
//
// D-01..D-04 are executable in this harness. D-10/D-12 are NOT — see the design
// note at the bottom of this file (no fake tests were written for them).

use frame_support::dispatch::{DispatchInfo, GetDispatchInfo, Pays, PostDispatchInfo};
use frame_support::weights::Weight;
use frame_support::assert_ok;
use frame_support::pallet_prelude::Zero;
use pallet_balances::Call as BalancesCall;
use pallet_relayer::{RelayTxNonces, Subsidies, Subsidy};
use polymesh_primitives::crypto::{ChainScopedMessage, RELAY_TX_LABEL};
use polymesh_primitives::multisig::ProposalState;
use polymesh_primitives::protocol_fee::ProtocolOp;
use polymesh_primitives::traits::{CurrentFeePayer, SubsidiserTrait};
use polymesh_primitives::{AccountId, Balance, Signatory, TransactionError};
use polymesh_primitives::constants::currency::POLY;
use sp_keyring::Sr25519Keyring;
use sp_runtime::traits::{Dispatchable, TransactionExtension, TxBaseImplication};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidityError,
};
use sp_runtime::{MultiAddress, MultiSignature};

use super::multisig::{create_multisig_default_perms, create_signers};
use super::storage::{
    get_last_auth_id, register_keyring_account_with_balance, EventTest, RuntimeCall, System,
    TestStorage, User,
};
use super::ExtBuilder;

type Relayer = pallet_relayer::Pallet<TestStorage>;
type MultiSig = pallet_multisig::Pallet<TestStorage>;
type Balances = pallet_balances::Pallet<TestStorage>;
type ProtocolFee = pallet_protocol_fee::Pallet<TestStorage>;
type ChargeTransactionPayment = polymesh_transaction_payment::ChargeTransactionPayment<TestStorage>;
type RelayerError = pallet_relayer::Error<TestStorage>;
type MultiSigError = pallet_multisig::Error<TestStorage>;
type RuntimeOrigin = <TestStorage as frame_system::Config>::RuntimeOrigin;

// ---------------------------------------------------------------------------
// Shared helpers (same patterns as relayer_test.rs / multisig.rs)
// ---------------------------------------------------------------------------

fn call_system_remark(size: usize) -> RuntimeCall {
    RuntimeCall::System(frame_system::Call::remark {
        remark: vec![0; size],
    })
}

fn call_utility_batch_all(calls: Vec<RuntimeCall>) -> RuntimeCall {
    RuntimeCall::Utility(pallet_utility::Call::batch_all { calls })
}

fn info_from_weight(w: u64) -> DispatchInfo {
    DispatchInfo {
        call_weight: Weight::from_parts(w, 0),
        ..Default::default()
    }
}

fn post_info_from_weight(w: u64) -> PostDispatchInfo {
    PostDispatchInfo {
        actual_weight: Some(Weight::from_parts(w, 0)),
        pays_fee: Pays::Yes,
    }
}

fn get_subsidy(user: &AccountId) -> Option<Subsidy<AccountId>> {
    Subsidies::<TestStorage>::get(user)
}

/// Setup a subsidy with `payer` paying for `user` (same as relayer_test.rs).
#[track_caller]
fn setup_subsidy(user: User, payer: User, limit: Balance) {
    assert_ok!(Relayer::approve_subsidy(payer.origin(), user.acc(), limit));
    assert_ok!(Relayer::accept_subsidy(user.origin(), payer.acc()));
    assert_eq!(
        get_subsidy(&user.acc()).map(|s| (s.paying_key, s.remaining)),
        Some((payer.acc(), limit))
    );
}

fn has_subsidy_debited(user_key: &AccountId, paying_key: &AccountId) -> bool {
    System::events().iter().any(|e| {
        matches!(
            &e.event,
            EventTest::Relayer(pallet_relayer::Event::SubsidyDebited {
                user_key: uk,
                paying_key: pk,
                ..
            }) if uk == user_key && pk == paying_key
        )
    })
}

/// Run `call` as a full signed extrinsic through the transaction-payment
/// extension (validate -> prepare -> dispatch -> post_dispatch), exactly as
/// relayer_test.rs does. Returns the dispatch result.
fn dispatch_with_payment(
    origin: RuntimeOrigin,
    call: RuntimeCall,
    call_weight: u64,
    len: usize,
) -> frame_support::dispatch::DispatchResultWithPostInfo {
    let call_info = info_from_weight(call_weight);
    let val = ChargeTransactionPayment::from(0)
        .validate(
            origin.clone(),
            &call,
            &call_info,
            len,
            Default::default(),
            &TxBaseImplication(()),
            TransactionSource::InBlock,
        )
        .unwrap();
    let pre = ChargeTransactionPayment::from(0)
        .prepare(val.1, &origin, &call, &call_info, len)
        .unwrap();
    let result = call.dispatch(origin);
    let mapped = result
        .as_ref()
        .map(|_| ())
        .map_err(|e| e.error);
    let mut post_info = post_info_from_weight(50);
    assert_ok!(ChargeTransactionPayment::post_dispatch(
        pre,
        &call_info,
        &mut post_info,
        len,
        &mapped,
    ));
    result
}

// ---------------------------------------------------------------------------
// D-01 (MEDIUM): SubsidyCallFilter bypass via multisig proposal.
// The filter only sees the outer call (`MultiSig::approve` /
// `create_proposal` => allowed), never the proposal inside, so a subsidised
// multisig paying key ends up paying fees for excluded calls.
// ---------------------------------------------------------------------------

#[test]
fn wave22_d01_subsidy_filter_bypass_via_multisig() {
    ExtBuilder::default()
        .monied(true)
        .transaction_fees(5, 1, 1)
        .build()
        .execute_with(&do_wave22_d01);
}

fn do_wave22_d01() {
    System::set_block_number(1);
    // A = subsidiser (Alice), K = subsidised paying key (Bob),
    // Attacker = multisig signer (Dave — raw account, see below).
    let alice = User::new(Sr25519Keyring::Alice);
    let k = User::new(Sr25519Keyring::Bob);
    // RUN 5 FIX: the attacker MUST be a raw account with no identity.
    // `User::new(Charlie)` registers Charlie's key as the primary key of
    // its own DID, and `base_accept_multisig_signer`
    // (pallets/multisig/src/lib.rs) rejects any signer key already linked
    // to an identity (`SignerAlreadyLinkedToIdentity`): a multisig signer
    // is a bare key, never a DID holder. The repo's own multisig tests use
    // raw keyring accounts as signers for the same reason
    // (pallets/runtime/tests/src/multisig.rs `create_multisig_required_signers`).
    // Dave is unused in this test and has no DID here.
    let attacker = Sr25519Keyring::Dave.to_account_id();
    let attacker_origin = RuntimeOrigin::signed(attacker.clone());

    let limit = 100 * POLY;
    setup_subsidy(k, alice, limit);

    // Control (validate level): a directly submitted excluded call from K is
    // rejected by the subsidy filter — it must NOT be subsidised.
    let direct = call_system_remark(8);
    let direct_err = ChargeTransactionPayment::from(0)
        .validate(
            RuntimeOrigin::signed(k.acc()),
            &direct,
            &info_from_weight(5),
            10,
            Default::default(),
            &TxBaseImplication(()),
            TransactionSource::InBlock,
        )
        .map(|_| ())
        .unwrap_err();
    let control_rejected = direct_err
        == TransactionValidityError::Invalid(InvalidTransaction::Custom(
            TransactionError::PalletNotSubsidised as u8,
        ));
    assert!(
        control_rejected,
        "control: direct excluded call from K must be rejected with PalletNotSubsidised, got {direct_err:?}"
    );

    // Multisig M created BY K, so its paying DID is K's DID and the fee payer
    // for multisig calls is K's primary key (= K). Signers {K, Attacker},
    // 1-of-1, so the attacker's proposal executes immediately.
    let ms_address = create_multisig_default_perms(
        k.acc(),
        create_signers(vec![k.acc(), attacker.clone()]),
        1,
    );
    let auth_id = get_last_auth_id(&Signatory::Account(attacker.clone()));
    assert_ok!(MultiSig::accept_multisig_signer(
        attacker_origin.clone(),
        auth_id
    ));
    // Sanity: the multisig's fee payer really is K.
    // (`CurrentFeePayer` is implemented for `TestStorage` in storage.rs and
    // delegates to the shared `TxFeeHandler`.)
    assert_eq!(
        TestStorage::call_payment_info(
            &RuntimeCall::MultiSig(pallet_multisig::Call::create_proposal {
                multisig: ms_address.clone(),
                proposal: Box::new(call_system_remark(1)),
                expiry: None,
            }),
            attacker.clone(),
        )
        .map(|info| info.paying_account().clone()),
        Ok(k.acc()),
        "multisig fee payer must be K (paying-DID primary key)"
    );

    let alice_before = Balances::free_balance(&alice.acc());
    let k_before = Balances::free_balance(&k.acc());
    let attacker_before = Balances::free_balance(&attacker);
    let remaining_before = get_subsidy(&k.acc()).unwrap().remaining;

    // The excluded payload: Utility::batch_all of System remarks — Utility
    // (non-batch) / System are both outside SubsidyFilter, so a direct
    // submission would never be subsidised (see control above).
    let inner = call_utility_batch_all(vec![
        call_system_remark(8),
        call_system_remark(8),
        call_system_remark(8),
    ]);
    let call = RuntimeCall::MultiSig(pallet_multisig::Call::create_proposal {
        multisig: ms_address.clone(),
        proposal: Box::new(inner),
        expiry: None,
    });
    let dispatch_result = dispatch_with_payment(attacker_origin, call, 100, 10);
    let dispatch_ok = dispatch_result.is_ok();
    assert!(
        dispatch_ok,
        "multisig create_proposal must dispatch Ok, got {dispatch_result:?}"
    );

    let remaining_after = get_subsidy(&k.acc()).unwrap().remaining;
    let alice_paid = alice_before - Balances::free_balance(&alice.acc());
    let k_paid = k_before - Balances::free_balance(&k.acc());
    let attacker_paid = attacker_before - Balances::free_balance(&attacker);
    let subsidy_spent = remaining_before - remaining_after;
    let proposal_executed = pallet_multisig::ProposalStates::<TestStorage>::get(&ms_address, 0)
        == Some(ProposalState::ExecutionSuccessful);
    let event_seen = has_subsidy_debited(&k.acc(), &alice.acc());

    // CONFIRMED iff the excluded batch executed AND the whole fee came out of
    // A's subsidy (Alice's balance down by exactly the subsidy spend, K and
    // the attacker paid nothing).
    let confirmed = dispatch_ok
        && proposal_executed
        && subsidy_spent > 0
        && alice_paid == subsidy_spent
        && k_paid == 0
        && attacker_paid == 0
        && event_seen;
    println!(
        "WAVE22 D-01: {} subsidy_spent={} alice_paid={} k_paid={} attacker_paid={} proposal_executed={} subsidy_debited_event={}",
        if confirmed { "CONFIRMED" } else { "REFUTED" },
        subsidy_spent,
        alice_paid,
        k_paid,
        attacker_paid,
        proposal_executed,
        event_seen,
    );
    assert!(
        confirmed,
        "D-01: expected the excluded batch to execute with the fee debited from A's subsidy"
    );
}

// ---------------------------------------------------------------------------
// D-02 (MEDIUM): protocol fees ignore the subsidy filter.
// `pallet_protocol_fee::withdraw_fee` calls
// `check_subsidy(&account, fee, None)` — with `None` the filter check in
// `check_subsidy` is skipped, so any subsidy with enough `remaining` pays
// the protocol fee, even for excluded calls.
// ---------------------------------------------------------------------------

#[test]
fn wave22_d02_protocol_fee_ignores_subsidy_filter() {
    ExtBuilder::default()
        .monied(true)
        .build()
        .execute_with(&do_wave22_d02);
}

fn do_wave22_d02() {
    System::set_block_number(1);
    let alice = User::new(Sr25519Keyring::Alice);
    let k = User::new(Sr25519Keyring::Bob);

    let limit = 100 * POLY;
    setup_subsidy(k, alice, limit);

    let fee = ProtocolFee::compute_fee(&[ProtocolOp::AssetCreateAsset]);
    assert!(fee > 0, "protocol fee for AssetCreateAsset must be > 0");

    // Contrast at the check_subsidy level (same user, same fee):
    //  - Some(excluded call)  -> filter applies -> Err(PalletNotSubsidised)
    //  - None (protocol-fee path) -> filter skipped -> Ok(Some(subsidiser))
    let excluded = call_system_remark(8);
    let with_call =
        <Relayer as SubsidiserTrait<AccountId, RuntimeCall>>::check_subsidy(
            &k.acc(),
            fee,
            Some(&excluded),
        );
    let filter_applies = with_call
        == Err(InvalidTransaction::Custom(
            TransactionError::PalletNotSubsidised as u8,
        ));
    let without_call =
        <Relayer as SubsidiserTrait<AccountId, RuntimeCall>>::check_subsidy(
            &k.acc(), fee, None,
        );
    let filter_skipped = without_call == Ok(Some(alice.acc()));

    // End-to-end through the real protocol-fee path: set the payer context to
    // K (as transaction-payment does during dispatch) and charge a protocol
    // fee. `withdraw_fee` is the exact call site that passes `None`.
    let alice_before = Balances::free_balance(&alice.acc());
    let k_before = Balances::free_balance(&k.acc());
    let remaining_before = get_subsidy(&k.acc()).unwrap().remaining;
    TestStorage::set_payer_context(Some(k.acc()));
    let charge = ProtocolFee::charge_fees(&[ProtocolOp::AssetCreateAsset]);
    TestStorage::set_payer_context(None);
    assert!(
        charge.is_ok(),
        "charge_fees must succeed, got {charge:?}"
    );

    let remaining_after = get_subsidy(&k.acc()).unwrap().remaining;
    let alice_paid = alice_before - Balances::free_balance(&alice.acc());
    let k_paid = k_before - Balances::free_balance(&k.acc());
    let subsidy_spent = remaining_before - remaining_after;
    let fee_charged_event = System::events().iter().any(|e| {
        matches!(
            &e.event,
            EventTest::ProtocolFee(pallet_protocol_fee::Event::FeeCharged(fee_key, amount))
                if *fee_key == alice.acc() && *amount == fee
        )
    });

    let confirmed = filter_applies
        && filter_skipped
        && subsidy_spent == fee
        && alice_paid == fee
        && k_paid == 0
        && fee_charged_event;
    println!(
        "WAVE22 D-02: {} fee={} subsidy_spent={} alice_paid={} k_paid={} filter_applies_with_call={} filter_skipped_with_none={} fee_charged_event={}",
        if confirmed { "CONFIRMED" } else { "REFUTED" },
        fee,
        subsidy_spent,
        alice_paid,
        k_paid,
        filter_applies,
        filter_skipped,
        fee_charged_event,
    );
    assert!(
        confirmed,
        "D-02: expected the protocol fee to be debited from A's subsidy despite the excluded call"
    );
}

// ---------------------------------------------------------------------------
// D-03 (LOW): relay_tx burns the target's nonce on an invalid signature.
// `RelayTxNonces::mutate` runs BEFORE `verify_signature` is checked, so a
// failed relay still consumes the nonce and invalidates pre-signed messages.
//
// METHOD NOTE (important): this test dispatches through `RuntimeCall` on
// purpose. A direct `Relayer::relay_tx(...)` pallet-fn call bypasses the
// storage-transaction wrapper that real extrinsics get, so it would show the
// nonce burn even if on-chain behaviour rolls it back. Dispatching through
// `RuntimeCall` gives the same transactional semantics as a real extrinsic
// (precedent: `approve_max_weight_too_low_charges_decode_cost` in
// `multisig.rs`, which asserts a failed approve rolls its vote back).
// If the extrinsic rolls back on InvalidSignature, the nonce is NOT burned
// and this test prints REFUTED — that is the honest on-chain verdict.
// ---------------------------------------------------------------------------

#[test]
fn wave22_d03_relay_tx_burns_nonce_on_bad_signature() {
    ExtBuilder::default()
        .build()
        .execute_with(&do_wave22_d03);
}

fn do_wave22_d03() {
    let alice = Sr25519Keyring::Alice.to_account_id();
    let _ = register_keyring_account_with_balance(Sr25519Keyring::Alice, 1_000).unwrap();
    let bob = Sr25519Keyring::Bob.to_account_id();
    let _ = register_keyring_account_with_balance(Sr25519Keyring::Bob, 1_000).unwrap();
    let charlie = Sr25519Keyring::Charlie.to_account_id();

    let origin = RuntimeOrigin::signed(alice);
    let expires_at = 100u64;

    // Target's pre-signed message for the CURRENT nonce (0).
    let call = Box::new(RuntimeCall::Balances(BalancesCall::transfer_allow_death {
        dest: MultiAddress::Id(charlie.clone()),
        value: 50,
    }));
    let nonce_before = RelayTxNonces::<TestStorage>::get(&bob);
    let scoped = ChainScopedMessage::<TestStorage, _>::new(
        nonce_before,
        RELAY_TX_LABEL,
        expires_at,
        &call,
    )
    .expect("message must not be expired");
    let valid_signature = scoped.sign(&Sr25519Keyring::Bob).expect("Bob must sign");

    // Attacker submits relay_tx with a garbage signature, dispatched as a
    // real extrinsic (RuntimeCall) so transactional rollback applies.
    let garbage = MultiSignature::Sr25519(Default::default());
    let attack_call = RuntimeCall::Relayer(pallet_relayer::Call::relay_tx {
        target: bob.clone(),
        signature: garbage,
        call: call.clone(),
        expires_at,
    });
    let attack_result = attack_call.dispatch(origin.clone());
    let attack_failed_invalid_sig = matches!(
        &attack_result,
        Err(e) if e.error == RelayerError::InvalidSignature.into()
    );
    assert!(
        attack_failed_invalid_sig,
        "relay_tx with garbage signature must fail with InvalidSignature, got {attack_result:?}"
    );
    let nonce_after_attack = RelayTxNonces::<TestStorage>::get(&bob);
    let nonce_burned = nonce_after_attack == nonce_before + 1;

    // The target's pre-signed message (nonce 0): rejected iff the nonce was
    // burned; accepted (relay executes) iff the failed extrinsic rolled back.
    let resubmit_call = RuntimeCall::Relayer(pallet_relayer::Call::relay_tx {
        target: bob.clone(),
        signature: valid_signature.into(),
        call: call.clone(),
        expires_at,
    });
    let resubmit_result = resubmit_call.dispatch(origin.clone());
    let old_message_rejected = matches!(
        &resubmit_result,
        Err(e) if e.error == RelayerError::InvalidSignature.into()
    );
    // The failed re-submission (if any) burned yet another nonce.
    let nonce_after_retry = RelayTxNonces::<TestStorage>::get(&bob);

    let confirmed = attack_failed_invalid_sig && nonce_burned && old_message_rejected;
    println!(
        "WAVE22 D-03: {} nonce_before={} nonce_after_attack={} nonce_after_retry={} old_message_rejected={} resubmit_ok={}",
        if confirmed { "CONFIRMED" } else { "REFUTED" },
        nonce_before,
        nonce_after_attack,
        nonce_after_retry,
        old_message_rejected,
        resubmit_result.is_ok(),
    );
    assert!(
        confirmed,
        "D-03: expected a failed relay_tx to consume the target nonce and invalidate the pre-signed message"
    );
}

// ---------------------------------------------------------------------------
// D-04 (LOW): multisig proposal destroyed by approving with too-low
// max_weight. `execute_proposal` does `Proposals::take` BEFORE the
// `proposal_weight.all_lte(max_weight)` check, so on MaxWeightTooLow the
// proposal is already gone from storage while ProposalStates still says
// Active — and a later approve fails with ProposalMissing.
//
// METHOD NOTE (important): this test dispatches through `RuntimeCall` on
// purpose. A direct `MultiSig::approve(...)` pallet-fn call bypasses the
// storage-transaction wrapper that real extrinsics get, so it would show the
// proposal destroyed even if on-chain behaviour rolls the `take` back. The
// repo's own test `approve_max_weight_too_low_charges_decode_cost`
// (`multisig.rs`) already dispatches via RuntimeCall and asserts the
// proposal SURVIVES a MaxWeightTooLow error (vote rolled back, proposal
// still Active) — i.e. the hunter's code-reading missed the transactional
// dispatch wrapper. If this test prints REFUTED, that matches the existing
// in-repo test and D-04 is dead as a finding.
// ---------------------------------------------------------------------------

#[test]
fn wave22_d04_approve_with_low_max_weight_destroys_proposal() {
    ExtBuilder::default()
        .build()
        .execute_with(&do_wave22_d04);
}

fn do_wave22_d04() {
    let alice = User::new(Sr25519Keyring::Alice);
    let ferdie = Sr25519Keyring::Ferdie.to_account_id();
    let bob = Sr25519Keyring::Bob.to_account_id();
    let charlie = Sr25519Keyring::Charlie.to_account_id();

    // 2-of-3 multisig; all three signers accept.
    let ms_address = create_multisig_default_perms(
        alice.acc(),
        create_signers(vec![ferdie.clone(), bob.clone(), charlie.clone()]),
        2,
    );
    for signer in [ferdie.clone(), bob.clone(), charlie.clone()] {
        let auth_id = get_last_auth_id(&Signatory::Account(signer.clone()));
        assert_ok!(MultiSig::accept_multisig_signer(
            RuntimeOrigin::signed(signer.clone()),
            auth_id
        ));
    }

    // S1 (Ferdie) creates proposal 0 (Balances transfer). 1-of-2 approvals:
    // not executed yet.
    let proposal = Box::new(RuntimeCall::Balances(BalancesCall::transfer_allow_death {
        dest: MultiAddress::Id(charlie.clone()),
        value: 1,
    }));
    assert_ok!(MultiSig::create_proposal(
        RuntimeOrigin::signed(ferdie.clone()),
        ms_address.clone(),
        proposal,
        None,
    ));
    assert!(
        pallet_multisig::Proposals::<TestStorage>::contains_key(&ms_address, 0),
        "proposal 0 must exist after creation"
    );
    let proposal_weight = pallet_multisig::Proposals::<TestStorage>::get(&ms_address, 0)
        .expect("proposal 0 stored")
        .get_dispatch_info()
        .call_weight;
    assert!(
        !proposal_weight.is_zero(),
        "proposal weight must be > 0 for the max_weight=0 repro to be meaningful"
    );

    // S2 (Bob) approves with max_weight = 0, dispatched as a real extrinsic
    // (RuntimeCall) so transactional rollback applies, exactly like the
    // in-repo test `approve_max_weight_too_low_charges_decode_cost`.
    let approve_call = RuntimeCall::MultiSig(pallet_multisig::Call::approve {
        multisig: ms_address.clone(),
        proposal_id: 0,
        max_weight: Some(Weight::zero()),
    });
    let approve_result = approve_call.dispatch(RuntimeOrigin::signed(bob.clone()));
    let failed_max_weight = matches!(
        &approve_result,
        Err(e) if e.error == MultiSigError::MaxWeightTooLow.into()
    );
    assert!(
        failed_max_weight,
        "approve with max_weight=0 must fail with MaxWeightTooLow, got {approve_result:?}"
    );
    let proposal_gone =
        !pallet_multisig::Proposals::<TestStorage>::contains_key(&ms_address, 0);
    let state_still_active = pallet_multisig::ProposalStates::<TestStorage>::get(&ms_address, 0)
        == Some(ProposalState::Active { until: None });

    // A later approve (S3, Charlie, generous weight) must fail ProposalMissing
    // iff the proposal was really destroyed.
    let reapprove_call = RuntimeCall::MultiSig(pallet_multisig::Call::approve {
        multisig: ms_address.clone(),
        proposal_id: 0,
        max_weight: None,
    });
    let reapprove_result = reapprove_call.dispatch(RuntimeOrigin::signed(charlie.clone()));
    let reapprove_missing = matches!(
        &reapprove_result,
        Err(e) if e.error == MultiSigError::ProposalMissing.into()
    );

    let confirmed = failed_max_weight && proposal_gone && state_still_active && reapprove_missing;
    println!(
        "WAVE22 D-04: {} proposal_weight={:?} proposal_gone={} state_still_active={} reapprove_proposal_missing={} reapprove_ok={}",
        if confirmed { "CONFIRMED" } else { "REFUTED" },
        proposal_weight,
        proposal_gone,
        state_still_active,
        reapprove_missing,
        reapprove_result.is_ok(),
    );
    assert!(
        confirmed,
        "D-04: expected approve(max_weight=0) to delete the proposal while its state stays Active"
    );
}

// ---------------------------------------------------------------------------
// D-10 / D-12 — NOT TESTABLE AS UNIT TESTS IN THIS HARNESS (design note).
//
// What was verified from source:
// - `pallet_revive` IS wired into the mock runtime: `TestStorage`
//   construct_runtime has `Revive` at pallet index 80, and the `Precompiles`
//   tuple in `pallets/runtime/tests/src/storage.rs` contains
//   `FungibleAssetInterface`, `NonFungibleAssetInterface` and
//   `PolymeshRuntimeInterface` (the `pallet_revive::Config` impl itself comes
//   from the shared macro in `pallets/runtime/common/src/runtime.rs:483`).
// - BUT there is no in-repo precedent for driving a precompile call
//   in-process: the only `pallet_revive::Call` use in Rust code is
//   `eth_substrate_call` in the subsidy filter, and every precompile test in
//   `integration/tests/revive_*.rs` drives the precompile through a LIVE node
//   + eth-rpc (`revive_tester()`, `SubstrateCaller`, alloy bindings).
// - The pinned polkadot-sdk fork source (`polymesh-v8-stable2603-7`) is NOT
//   vendored locally, so the exact `pallet_revive::Call::{call, eth_transact}`
//   / `bare_call` signatures, gas-limit / storage-deposit args, and the
//   eth-origin mapping (`AccountId32Mapper`) could NOT be verified from
//   source. Writing a `Revive::call` to the precompile address here would be
//   guessing API — a test that does not compile breaks the whole CI file, and
//   a test that calls the precompile trait directly (bypassing revive) would
//   NOT test the question at all, because the transactional rollback (if any)
//   lives in revive's call frame, not in the precompile.
// - Therefore: no fake `#[test]` was written for D-10/D-12. The designs
//   below are for the node-based route (integration tests), which is the
//   honest way to settle both items.
//
// D-10 design (node-based, extend `integration/tests/revive_erc3643.rs`,
// `erc3643_set_symbol`): create an asset via `create_erc20_asset`, then call
// `setSymbol` in a way that ONLY the final `link_ticker_to_asset_id` step
// fails, and read back whether the new ticker stayed registered
// (`Asset::UniqueTickerRegistration` / `TickerAssetId`) —
//   * CONFIRMED if the ticker is registered but unlinked (partial state),
//   * REFUTED if the whole `setSymbol` reverted atomically.
//   Failure-injection problem (found while designing): after a successful
//   `register_unique_ticker` + `unlink_ticker_from_asset_id`, the link step
//   has almost no failing path left — `base_link_ticker_to_asset_id`
//   (`pallets/asset/src/lib.rs:3019`) fails only on perms, an expired
//   registration, `ensure_ticker_not_linked`, or `AssetIsAlreadyLinkedToATicker`,
//   and `set_symbol` itself unlinks the old ticker first, so the last two
//   cannot trigger in a single-threaded call. No reliable public-extrinsic
//   trigger for a link-only failure was found; this item may be
//   untriggerable in practice even on a node, unless the link is forced to
//   fail another way (e.g. racing a second `setSymbol`, or an expiry edge).
//   That difficulty is itself evidence the worst case is narrow.
//
// D-12 design (node-based, extend `integration/tests/revive_erc20.rs`):
// create + issue an asset, give a second DID a balance, then do a cross-DID
// `transfer` via the precompile where the settlement instruction is created
// but NOT executed (receiver has not affirmed / compliance blocks execution,
// so `transfer_funds` returns `inst_id.is_some()` and the precompile reverts
// with `ERR_INST_NOT_EXECUTED`). Then read settlement storage for that
// instruction id —
//   * CONFIRMED if the instruction still exists (dangling, funds locked /
//     affirmation pending) after the revert,
//   * REFUTED if it is gone (revive rolled the whole call back).
//   This injection is realistic (unlike D-10's), so D-12 is the better
//   node-test candidate of the two.
//
// Node-based cost estimate (per repo `AGENTS.md`): one release node build
// (`cargo build --locked --release --features ci-runtime`, slow — builds
// three runtime WASMs), a dev node (`--bob --dev --tmp`) plus the eth-rpc
// docker container (`paritypr/eth-rpc`, WS :9944 / HTTP :8545), then
// `cd integration && cargo nextest run --release --features
// current_release,timed` for the new/changed revive tests. No new
// infrastructure beyond what the repo already documents.
