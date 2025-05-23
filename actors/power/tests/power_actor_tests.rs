use fil_actor_power::ext::init::{EXEC_METHOD, ExecParams};
use fil_actor_power::ext::miner::MinerConstructorParams;
use fil_actors_runtime::runtime::builtins::Type;
use fil_actors_runtime::test_utils::{
    ACCOUNT_ACTOR_CODE_ID, EVM_ACTOR_CODE_ID, MINER_ACTOR_CODE_ID, SYSTEM_ACTOR_CODE_ID,
    expect_abort, expect_abort_contains_message,
};
use fil_actors_runtime::{INIT_ACTOR_ADDR, runtime::Policy};
use fvm_ipld_encoding::{BytesDe, RawBytes};
use fvm_shared::MethodNum;
use fvm_shared::address::Address;
use fvm_shared::bigint::bigint_ser::BigIntSer;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::sector::{RegisteredPoStProof, StoragePower};
use num_traits::Zero;
use std::ops::Neg;

use fil_actor_power::{
    Actor as PowerActor, Actor, CONSENSUS_MINER_MIN_MINERS, CreateMinerParams, CreateMinerReturn,
    EnrollCronEventParams, Method, MinerPowerParams, MinerPowerReturn, MinerRawPowerParams,
    MinerRawPowerReturn, NetworkRawPowerReturn, State, UpdateClaimedPowerParams,
    consensus_miner_min_power,
};

use fvm_ipld_encoding::ipld_block::IpldBlock;

use crate::harness::*;

mod harness;

#[test]
fn construct() {
    let rt = new_runtime();
    let h = new_harness();
    h.construct_and_verify(&rt);
    h.check_state(&rt);
}

#[test]
fn create_miner() {
    let (h, rt) = setup();

    let peer = "miner".as_bytes().to_vec();
    let multiaddrs = vec![BytesDe("multiaddr".as_bytes().to_vec())];

    h.create_miner(
        &rt,
        &OWNER,
        &OWNER,
        &MINER,
        &ACTOR,
        peer,
        multiaddrs,
        RegisteredPoStProof::StackedDRGWindow32GiBV1P1,
        &TokenAmount::from_atto(10),
    )
    .unwrap();

    let st: State = rt.get_state();
    // Verify the miner's claim.
    let claim = h.get_claim(&rt, &MINER).unwrap();
    assert_eq!(RegisteredPoStProof::StackedDRGWindow32GiBV1P1, claim.window_post_proof_type);
    assert_eq!(StoragePower::zero(), claim.raw_byte_power);
    assert_eq!(StoragePower::zero(), claim.quality_adj_power);

    // Verify aggregates.
    let miners = h.list_miners(&rt);
    assert_eq!(1, miners.len());
    assert_eq!(1, st.miner_count);
    assert_eq!(StoragePower::zero(), st.total_quality_adj_power);
    assert_eq!(StoragePower::zero(), st.total_raw_byte_power);
    assert_eq!(StoragePower::zero(), st.total_bytes_committed);
    assert_eq!(StoragePower::zero(), st.total_qa_bytes_committed);
    assert_eq!(TokenAmount::zero(), st.total_pledge_collateral);
    assert_eq!(0, st.miner_above_min_power_count);

    verify_empty_map(&rt, st.cron_event_queue);
    h.check_state(&rt);
}

#[test]
fn create_miner_given_send_to_init_actor_fails_should_fail() {
    let (h, rt) = setup();

    let peer = "miner".as_bytes().to_vec();
    let multiaddrs = vec![BytesDe("multiaddr".as_bytes().to_vec())];

    let create_miner_params = CreateMinerParams {
        owner: *OWNER,
        worker: *OWNER,
        window_post_proof_type: RegisteredPoStProof::StackedDRGWindow32GiBV1P1,
        peer: peer.clone(),
        multiaddrs: multiaddrs.clone(),
    };

    // owner send CreateMiner to Actor
    rt.set_caller(*ACCOUNT_ACTOR_CODE_ID, *OWNER);
    rt.value_received.replace(TokenAmount::from_atto(10));
    rt.set_balance(TokenAmount::from_atto(10));
    rt.expect_validate_caller_any();

    let message_params = ExecParams {
        code_cid: *MINER_ACTOR_CODE_ID,
        constructor_params: RawBytes::serialize(MinerConstructorParams {
            owner: *OWNER,
            worker: *OWNER,
            window_post_proof_type: RegisteredPoStProof::StackedDRGWindow32GiBV1P1,
            peer_id: peer,
            multi_addresses: multiaddrs,
            control_addresses: Default::default(),
        })
        .unwrap(),
    };

    rt.expect_send_simple(
        INIT_ACTOR_ADDR,
        EXEC_METHOD,
        IpldBlock::serialize_cbor(&message_params).unwrap(),
        TokenAmount::from_atto(10),
        None,
        ExitCode::USR_INSUFFICIENT_FUNDS,
    );

    expect_abort(
        ExitCode::USR_INSUFFICIENT_FUNDS,
        rt.call::<PowerActor>(
            Method::CreateMiner as u64,
            IpldBlock::serialize_cbor(&create_miner_params).unwrap(),
        ),
    );
    rt.verify();
    h.check_state(&rt);
}

#[test]
fn claimed_power_given_caller_is_not_storage_miner_should_fail() {
    let (h, rt) = setup();

    let params = UpdateClaimedPowerParams {
        raw_byte_delta: StoragePower::from(100),
        quality_adjusted_delta: StoragePower::from(200),
    };

    rt.set_caller(*SYSTEM_ACTOR_CODE_ID, *MINER);
    rt.expect_validate_caller_type(vec![Type::Miner]);

    expect_abort(
        ExitCode::USR_FORBIDDEN,
        rt.call::<PowerActor>(
            Method::UpdateClaimedPower as u64,
            IpldBlock::serialize_cbor(&params).unwrap(),
        ),
    );

    rt.verify();
    h.check_state(&rt);
}

#[test]
fn claimed_power_given_claim_does_not_exist_should_fail() {
    let (h, rt) = setup();

    let params = UpdateClaimedPowerParams {
        raw_byte_delta: StoragePower::from(100),
        quality_adjusted_delta: StoragePower::from(200),
    };

    rt.set_caller(*MINER_ACTOR_CODE_ID, *MINER);
    rt.expect_validate_caller_type(vec![Type::Miner]);

    expect_abort(
        ExitCode::USR_NOT_FOUND,
        rt.call::<PowerActor>(
            Method::UpdateClaimedPower as u64,
            IpldBlock::serialize_cbor(&params).unwrap(),
        ),
    );

    rt.verify();
    h.check_state(&rt);
}

const MINER1: Address = Address::new_id(111);
const MINER2: Address = Address::new_id(112);
const MINER3: Address = Address::new_id(113);
const MINER4: Address = Address::new_id(114);
const MINER5: Address = Address::new_id(115);

#[test]
fn power_and_pledge_accounted_below_threshold() {
    assert_eq!(CONSENSUS_MINER_MIN_MINERS, 4);

    let small_power_unit = &StoragePower::from(1_000_000);
    let small_power_unit_x2 = &(small_power_unit * 2);
    let small_power_unit_x3 = &(small_power_unit * 3);

    let (mut h, rt) = setup();

    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER1).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER2).unwrap();

    let ret = h.current_power_total(&rt);
    assert_eq!(StoragePower::zero(), ret.raw_byte_power);
    assert_eq!(StoragePower::zero(), ret.quality_adj_power);
    assert_eq!(TokenAmount::zero(), ret.pledge_collateral);

    // Add power for miner1
    h.update_claimed_power(&rt, MINER1, small_power_unit, small_power_unit_x2);
    h.expect_total_power_eager(&rt, small_power_unit, small_power_unit_x2);

    // Add power and pledge for miner2
    h.update_claimed_power(&rt, MINER2, small_power_unit, small_power_unit);
    h.update_pledge_total(&rt, MINER1, &TokenAmount::from_atto(1_000_000));
    h.expect_total_power_eager(&rt, small_power_unit_x2, small_power_unit_x3);
    h.expect_total_pledge_eager(&rt, &TokenAmount::from_atto(1_000_000));

    rt.verify();

    // Verify claims in state.
    let claim1 = h.get_claim(&rt, &MINER1).unwrap();
    assert_eq!(small_power_unit, &claim1.raw_byte_power);
    assert_eq!(small_power_unit_x2, &claim1.quality_adj_power);

    let claim2 = h.get_claim(&rt, &MINER2).unwrap();
    assert_eq!(small_power_unit, &claim2.raw_byte_power);
    assert_eq!(small_power_unit, &claim2.quality_adj_power);

    // Subtract power and some pledge for miner2
    h.update_claimed_power(&rt, MINER2, &small_power_unit.neg(), &small_power_unit.neg());
    h.update_pledge_total(&rt, MINER2, &TokenAmount::from_atto(100_000).neg());
    h.expect_total_power_eager(&rt, small_power_unit, small_power_unit_x2);
    h.expect_total_pledge_eager(&rt, &TokenAmount::from_atto(900_000));

    let claim2 = h.get_claim(&rt, &MINER2).unwrap();
    assert!(claim2.raw_byte_power.is_zero());
    assert!(claim2.quality_adj_power.is_zero());
    h.check_state(&rt);
}

#[test]
fn enroll_cron_epoch_multiple_events() {
    let (mut h, rt) = setup();

    h.create_miner_basic(&rt, *OWNER, *OWNER, *MINER).unwrap();
    let miner2_address = Address::new_id(501);
    h.create_miner_basic(&rt, *OWNER, *OWNER, miner2_address).unwrap();

    let enroll_and_check_cron_event = |epoch, miner_address, payload| {
        let pre_existing_event_count = h.get_enrolled_cron_ticks(&rt, epoch).len();

        h.enroll_cron_event(&rt, epoch, miner_address, payload).unwrap();

        let events = h.get_enrolled_cron_ticks(&rt, epoch);
        assert_eq!(events.len(), pre_existing_event_count + 1);
        assert_eq!(&events.last().unwrap().callback_payload, payload);
        assert_eq!(&events.last().unwrap().miner_addr, miner_address);
    };

    // enroll event with miner 1
    let payload = RawBytes::serialize(b"Cthulhu").unwrap();
    enroll_and_check_cron_event(1, &MINER, &payload);

    // enroll another event with the same miner
    let payload = RawBytes::serialize(b"Nyarlathotep").unwrap();
    enroll_and_check_cron_event(1, &MINER, &payload);

    // enroll another event with a different miner for a different epoch
    let payload = RawBytes::serialize(b"Azathoth").unwrap();
    enroll_and_check_cron_event(2, &miner2_address, &payload);

    h.check_state(&rt);
}

#[test]
fn enroll_cron_epoch_before_current_epoch() {
    let (mut h, rt) = setup();

    h.create_miner_basic(&rt, *OWNER, *OWNER, *MINER).unwrap();

    let current_epoch: ChainEpoch = 5;
    rt.set_epoch(current_epoch);

    // enroll event with miner at epoch=2
    let miner_epoch = 2;
    let payload = RawBytes::serialize(b"Cthulhu").unwrap();
    h.enroll_cron_event(&rt, miner_epoch, &MINER, &payload).unwrap();

    let events = h.get_enrolled_cron_ticks(&rt, miner_epoch);
    assert_eq!(events.len(), 1);
    assert_eq!(&events.last().unwrap().callback_payload, &payload);
    assert_eq!(events.last().unwrap().miner_addr, *MINER);

    let state: State = rt.get_state();
    assert_eq!(state.first_cron_epoch, 0);

    // enroll event with miner at epoch=1
    let miner_epoch = 1;
    let payload = RawBytes::serialize(b"Azathoth").unwrap();
    h.enroll_cron_event(&rt, miner_epoch, &MINER, &payload).unwrap();

    let events = h.get_enrolled_cron_ticks(&rt, miner_epoch);
    assert_eq!(events.len(), 1);
    assert_eq!(&events.last().unwrap().callback_payload, &payload);
    assert_eq!(events.last().unwrap().miner_addr, *MINER);

    let state: State = rt.get_state();
    assert_eq!(state.first_cron_epoch, 0);

    rt.verify();
    h.check_state(&rt);
}

#[test]
fn new_miner_updates_miner_above_min_power_count() {
    struct TestCase {
        proof: RegisteredPoStProof,
        expected_miners: i64,
    }

    let test_cases = [
        TestCase { proof: RegisteredPoStProof::StackedDRGWindow2KiBV1P1, expected_miners: 0 },
        TestCase { proof: RegisteredPoStProof::StackedDRGWindow32GiBV1P1, expected_miners: 0 },
    ];

    for test in test_cases {
        let (mut h, rt) = setup();
        h.window_post_proof = test.proof;
        h.create_miner_basic(&rt, *OWNER, *OWNER, MINER1).unwrap();

        h.expect_miners_above_min_power(&rt, test.expected_miners);
        h.check_state(&rt);
    }
}

#[test]
fn power_accounting_crossing_threshold() {
    let small_power_unit = &StoragePower::from(1_000_000);
    let small_power_unit_x10 = &(small_power_unit * 10);

    let power_unit = &consensus_miner_min_power(
        &Policy::default(),
        RegisteredPoStProof::StackedDRGWindow32GiBV1P1,
    )
    .unwrap();
    let power_unit_x10 = &(power_unit * 10);

    assert!(small_power_unit < power_unit);

    let (mut h, rt) = setup();

    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER1).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER2).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER3).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER4).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER5).unwrap();

    // Use qa power 10x raw power to show it's not being used for threshold calculations.
    h.update_claimed_power(&rt, MINER1, small_power_unit, small_power_unit_x10);
    h.update_claimed_power(&rt, MINER2, small_power_unit, small_power_unit_x10);

    h.update_claimed_power(&rt, MINER3, power_unit, power_unit_x10);
    h.update_claimed_power(&rt, MINER4, power_unit, power_unit_x10);
    h.update_claimed_power(&rt, MINER5, power_unit, power_unit_x10);

    // Below threshold small miner power is counted
    let expected_total_below = small_power_unit * 2 + power_unit * 3;
    h.expect_total_power_eager(&rt, &expected_total_below, &(&expected_total_below * 10));

    // Above threshold (power.ConsensusMinerMinMiners = 4) small miner power is ignored
    let delta = &(power_unit - small_power_unit);
    h.update_claimed_power(&rt, MINER2, delta, &(delta * 10));
    let expected_total_above = &(power_unit * 4);
    h.expect_total_power_eager(&rt, expected_total_above, &(expected_total_above * 10));

    h.expect_miners_above_min_power(&rt, 4);

    // Less than 4 miners above threshold again small miner power is counted again
    h.update_claimed_power(&rt, MINER4, &delta.neg(), &(delta.neg() * 10));
    h.expect_total_power_eager(&rt, &expected_total_below, &(&expected_total_below * 10));
    h.check_state(&rt);
}

#[test]
fn all_of_one_miners_power_disappears_when_that_miner_dips_below_min_power_threshold() {
    let small_power_unit = &StoragePower::from(1_000_000);
    let power_unit = &consensus_miner_min_power(
        &Policy::default(),
        RegisteredPoStProof::StackedDRGWindow32GiBV1P1,
    )
    .unwrap();

    assert!(small_power_unit < power_unit);

    let (mut h, rt) = setup();

    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER1).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER2).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER3).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER4).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER5).unwrap();

    h.update_claimed_power(&rt, MINER1, power_unit, power_unit);
    h.update_claimed_power(&rt, MINER2, power_unit, power_unit);
    h.update_claimed_power(&rt, MINER3, power_unit, power_unit);
    h.update_claimed_power(&rt, MINER4, power_unit, power_unit);
    h.update_claimed_power(&rt, MINER5, power_unit, power_unit);

    let expected_total = &(power_unit * 5);
    h.expect_total_power_eager(&rt, expected_total, expected_total);

    // miner4 dips just below threshold
    h.update_claimed_power(&rt, MINER4, &small_power_unit.neg(), &small_power_unit.neg());

    let expected_total = &(power_unit * 4);
    h.expect_total_power_eager(&rt, expected_total, expected_total);
    h.check_state(&rt);
}

#[test]
fn enroll_cron_epoch_given_negative_epoch_should_fail() {
    let (h, rt) = setup();

    rt.set_caller(*MINER_ACTOR_CODE_ID, *MINER);
    rt.expect_validate_caller_type(vec![Type::Miner]);

    let params = EnrollCronEventParams {
        event_epoch: -1,
        payload: RawBytes::serialize(b"Cthulhu").unwrap(),
    };
    expect_abort(
        ExitCode::USR_ILLEGAL_ARGUMENT,
        rt.call::<PowerActor>(
            Method::EnrollCronEvent as u64,
            IpldBlock::serialize_cbor(&params).unwrap(),
        ),
    );

    rt.verify();
    h.check_state(&rt);
}

#[test]
fn power_gets_added_when_miner_crosses_min_power_but_not_before() {
    let power_unit = &consensus_miner_min_power(
        &Policy::default(),
        RegisteredPoStProof::StackedDRGWindow32GiBV1P1,
    )
    .unwrap();

    // Setup four miners above threshold
    let (mut h, rt) = setup();

    // create 4 miners that meet minimum
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER1).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER2).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER3).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER4).unwrap();

    h.update_claimed_power(&rt, MINER1, power_unit, power_unit);
    h.update_claimed_power(&rt, MINER2, power_unit, power_unit);
    h.update_claimed_power(&rt, MINER3, power_unit, power_unit);
    h.update_claimed_power(&rt, MINER4, power_unit, power_unit);

    h.expect_miners_above_min_power(&rt, 4);
    let expected_total = &(power_unit * 4);
    h.expect_total_power_eager(&rt, expected_total, expected_total);

    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER5).unwrap();
    let below_limit_unit = power_unit / 2;

    // below limit actors power is not added
    h.update_claimed_power(&rt, MINER5, &below_limit_unit, &below_limit_unit);
    h.expect_miners_above_min_power(&rt, 4);
    h.expect_total_power_eager(&rt, expected_total, expected_total);

    // just below limit
    let delta = power_unit - below_limit_unit - 1;
    h.update_claimed_power(&rt, MINER5, &delta, &delta);
    h.expect_miners_above_min_power(&rt, 4);
    h.expect_total_power_eager(&rt, expected_total, expected_total);

    // at limit power is added
    h.update_claimed_power(&rt, MINER5, &StoragePower::from(1), &StoragePower::from(1));
    h.expect_miners_above_min_power(&rt, 5);
    let new_expected_total = expected_total + power_unit;
    h.expect_total_power_eager(&rt, &new_expected_total, &new_expected_total);
    h.check_state(&rt);
}

#[test]
fn threshold_only_depends_on_raw_power_not_qa_power() {
    let power_unit = &consensus_miner_min_power(
        &Policy::default(),
        RegisteredPoStProof::StackedDRGWindow32GiBV1P1,
    )
    .unwrap();
    let half_power_unit = &(power_unit / 2);

    let (mut h, rt) = setup();

    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER1).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER2).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER3).unwrap();
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER4).unwrap();

    h.update_claimed_power(&rt, MINER1, half_power_unit, power_unit);
    h.update_claimed_power(&rt, MINER2, half_power_unit, power_unit);
    h.update_claimed_power(&rt, MINER3, half_power_unit, power_unit);
    h.expect_miners_above_min_power(&rt, 0);

    h.update_claimed_power(&rt, MINER1, half_power_unit, power_unit);
    h.update_claimed_power(&rt, MINER2, half_power_unit, power_unit);
    h.update_claimed_power(&rt, MINER3, half_power_unit, power_unit);
    h.expect_miners_above_min_power(&rt, 3);
    h.check_state(&rt);
}

#[test]
fn qa_power_is_above_threshold_before_and_after_update() {
    let power_unit = &consensus_miner_min_power(
        &Policy::default(),
        RegisteredPoStProof::StackedDRGWindow32GiBV1P1,
    )
    .unwrap();
    let power_unit_x3 = &(power_unit * 3);
    let power_unit_x4 = &(power_unit * 4);

    let (mut h, rt) = setup();

    // update claim so qa is above threshold
    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER1).unwrap();
    h.update_claimed_power(&rt, MINER1, power_unit_x3, power_unit_x3);
    let st: State = rt.get_state();
    assert_eq!(power_unit_x3, &st.total_quality_adj_power);
    assert_eq!(power_unit_x3, &st.total_raw_byte_power);

    // update such that it's above threshold again
    h.update_claimed_power(&rt, MINER1, power_unit, power_unit);
    let st: State = rt.get_state();
    assert_eq!(power_unit_x4, &st.total_quality_adj_power);
    assert_eq!(power_unit_x4, &st.total_raw_byte_power);
    h.check_state(&rt);
}

#[test]
fn claimed_power_is_externally_available() {
    let power_unit = &consensus_miner_min_power(
        &Policy::default(),
        RegisteredPoStProof::StackedDRGWindow32GiBV1P1,
    )
    .unwrap();

    let (mut h, rt) = setup();

    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER1).unwrap();
    h.update_claimed_power(&rt, MINER1, power_unit, power_unit);

    let claim = h.get_claim(&rt, &MINER1).unwrap();

    assert_eq!(power_unit, &claim.raw_byte_power);
    assert_eq!(power_unit, &claim.quality_adj_power);
    h.check_state(&rt);
}

#[test]
fn get_network_and_miner_power() {
    let power_unit = &consensus_miner_min_power(
        &Policy::default(),
        RegisteredPoStProof::StackedDRGWindow32GiBV1P1,
    )
    .unwrap();

    let (mut h, rt) = setup();

    h.create_miner_basic(&rt, *OWNER, *OWNER, MINER1).unwrap();
    h.update_claimed_power(&rt, MINER1, power_unit, power_unit);

    // manually update state in lieu of cron running
    let mut state: State = rt.get_state();
    state.this_epoch_raw_byte_power = power_unit.clone();
    rt.replace_state(&state);

    // set caller to not-builtin
    rt.set_caller(*EVM_ACTOR_CODE_ID, Address::new_id(1234));

    rt.expect_validate_caller_any();
    let network_power: NetworkRawPowerReturn = rt
        .call::<Actor>(Method::NetworkRawPowerExported as u64, None)
        .unwrap()
        .unwrap()
        .deserialize()
        .unwrap();

    assert_eq!(power_unit, &network_power.raw_byte_power);

    rt.expect_validate_caller_any();
    let miner_power: MinerRawPowerReturn = rt
        .call::<Actor>(
            Method::MinerRawPowerExported as u64,
            IpldBlock::serialize_cbor(&MinerRawPowerParams { miner: MINER1.id().unwrap() })
                .unwrap(),
        )
        .unwrap()
        .unwrap()
        .deserialize()
        .unwrap();

    assert_eq!(power_unit, &miner_power.raw_byte_power);

    h.update_claimed_power(&rt, MINER1, &StoragePower::zero(), power_unit);
    rt.expect_validate_caller_any();
    let miner_power: MinerPowerReturn = rt
        .call::<Actor>(
            Method::MinerPowerExported as u64,
            IpldBlock::serialize_cbor(&MinerPowerParams { miner: MINER1.id().unwrap() }).unwrap(),
        )
        .unwrap()
        .unwrap()
        .deserialize()
        .unwrap();

    let power_unit_x2 = &(power_unit * 2);
    assert_eq!(power_unit, &miner_power.raw_byte_power);
    assert_eq!(power_unit_x2, &miner_power.quality_adj_power);

    h.check_state(&rt);
}

#[test]
fn given_no_miner_claim_update_pledge_total_should_abort() {
    let (mut h, rt) = setup();

    h.create_miner_basic(&rt, *OWNER, *OWNER, *MINER).unwrap();

    // explicitly delete miner claim
    h.delete_claim(&rt, &MINER);

    rt.set_caller(*MINER_ACTOR_CODE_ID, *MINER);
    rt.expect_validate_caller_type(vec![Type::Miner]);
    expect_abort_contains_message(
        ExitCode::USR_FORBIDDEN,
        "unknown miner",
        rt.call::<PowerActor>(
            Method::UpdatePledgeTotal as u64,
            IpldBlock::serialize_cbor(&&TokenAmount::from_atto(1_000_000)).unwrap(),
        ),
    );

    rt.verify();
    h.check_state(&rt);
}

#[cfg(test)]
mod cron_tests {
    use super::*;

    use fil_actor_power::ext::reward::Method as RewardMethod;
    use fil_actor_power::ext::{
        miner::{DeferredCronEventParams, ON_DEFERRED_CRON_EVENT_METHOD},
        reward::UPDATE_NETWORK_KPI,
    };
    use fil_actors_runtime::{CRON_ACTOR_ADDR, REWARD_ACTOR_ADDR, test_utils::CRON_ACTOR_CODE_ID};
    use fvm_shared::bigint::BigInt;

    const OWNER: Address = Address::new_id(103);

    #[test]
    fn call_reward_actor() {
        let (h, rt) = setup();

        let expected_power = BigInt::zero();
        rt.set_epoch(1);

        rt.expect_validate_caller_addr(vec![CRON_ACTOR_ADDR]);

        h.expect_query_network_info(&rt);
        rt.expect_send_simple(
            REWARD_ACTOR_ADDR,
            RewardMethod::UpdateNetworkKPI as u64,
            IpldBlock::serialize_cbor(&BigIntSer(&expected_power)).unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::OK,
        );
        rt.set_caller(*CRON_ACTOR_CODE_ID, CRON_ACTOR_ADDR);

        rt.call::<PowerActor>(Method::OnEpochTickEnd as u64, None).unwrap();

        rt.verify();
        h.check_state(&rt);
    }

    #[test]
    fn amount_sent_to_reward_actor_and_state_change() {
        let (mut h, rt) = setup();
        let power_unit = consensus_miner_min_power(
            &Policy::default(),
            RegisteredPoStProof::StackedDRGWindow2KiBV1P1,
        )
        .unwrap();

        let miner1 = Address::new_id(101);
        let miner2 = Address::new_id(102);
        let miner3 = Address::new_id(103);
        let miner4 = Address::new_id(104);

        h.create_miner_basic(&rt, OWNER, OWNER, miner1).unwrap();
        h.create_miner_basic(&rt, OWNER, OWNER, miner2).unwrap();
        h.create_miner_basic(&rt, OWNER, OWNER, miner3).unwrap();
        h.create_miner_basic(&rt, OWNER, OWNER, miner4).unwrap();

        h.update_claimed_power(&rt, miner1, &power_unit, &power_unit);
        h.update_claimed_power(&rt, miner2, &power_unit, &power_unit);
        h.update_claimed_power(&rt, miner3, &power_unit, &power_unit);
        h.update_claimed_power(&rt, miner4, &power_unit, &power_unit);

        let expected_power: BigInt = power_unit * 4u8;

        let delta = TokenAmount::from_atto(1u8);
        h.update_pledge_total(&rt, miner1, &delta);
        h.on_epoch_tick_end(&rt, 0, &expected_power);

        let state: State = rt.get_state();

        assert_eq!(delta, state.this_epoch_pledge_collateral);
        assert_eq!(expected_power, state.this_epoch_quality_adj_power);
        assert_eq!(expected_power, state.this_epoch_raw_byte_power);

        rt.verify();
        h.check_state(&rt);
    }

    #[test]
    fn event_scheduled_in_null_round_called_next_round() {
        let (mut h, rt) = setup();

        let miner1 = Address::new_id(101);
        let miner2 = Address::new_id(102);

        h.create_miner_basic(&rt, OWNER, OWNER, miner1).unwrap();
        h.create_miner_basic(&rt, OWNER, OWNER, miner2).unwrap();

        //  0 - genesis
        //  1 - block - registers events
        //  2 - null  - has event
        //  3 - null
        //  4 - block - has event

        rt.set_epoch(1);
        h.enroll_cron_event(&rt, 2, &miner1, &RawBytes::from(vec![0x01, 0x03])).unwrap();
        h.enroll_cron_event(&rt, 4, &miner2, &RawBytes::from(vec![0x02, 0x03])).unwrap();

        let expected_raw_byte_power = BigInt::zero();
        rt.set_epoch(4);
        rt.expect_validate_caller_addr(vec![CRON_ACTOR_ADDR]);
        h.expect_query_network_info(&rt);
        let state: State = rt.get_state();

        let params1 = DeferredCronEventParams {
            event_payload: vec![0x01, 0x03],
            reward_smoothed: h.this_epoch_reward_smoothed.clone(),
            quality_adj_power_smoothed: state.this_epoch_qa_power_smoothed.clone(),
        };
        rt.expect_send_simple(
            miner1,
            ON_DEFERRED_CRON_EVENT_METHOD,
            IpldBlock::serialize_cbor(&params1).unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::OK,
        );

        let params2 = DeferredCronEventParams {
            event_payload: vec![0x02, 0x03],
            reward_smoothed: h.this_epoch_reward_smoothed.clone(),
            quality_adj_power_smoothed: state.this_epoch_qa_power_smoothed,
        };
        rt.expect_send_simple(
            miner2,
            ON_DEFERRED_CRON_EVENT_METHOD,
            IpldBlock::serialize_cbor(&params2).unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::OK,
        );

        rt.expect_send_simple(
            REWARD_ACTOR_ADDR,
            UPDATE_NETWORK_KPI,
            IpldBlock::serialize_cbor(&BigIntSer(&expected_raw_byte_power)).unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::OK,
        );
        rt.set_caller(*CRON_ACTOR_CODE_ID, CRON_ACTOR_ADDR);
        rt.call::<PowerActor>(Method::OnEpochTickEnd as u64, None).unwrap();

        rt.verify();
        h.check_state(&rt);
    }

    #[test]
    fn event_scheduled_in_past_called_next_round() {
        let (mut h, rt) = setup();

        let miner_addr = Address::new_id(101);
        h.create_miner_basic(&rt, OWNER, OWNER, miner_addr).unwrap();

        // run cron once to put it in a clean state at epoch 4
        let expected_raw_byte_power = BigInt::zero();
        rt.set_epoch(4);
        rt.expect_validate_caller_addr(vec![CRON_ACTOR_ADDR]);
        h.expect_query_network_info(&rt);
        rt.expect_send_simple(
            REWARD_ACTOR_ADDR,
            UPDATE_NETWORK_KPI,
            IpldBlock::serialize_cbor(&BigIntSer(&expected_raw_byte_power)).unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::OK,
        );
        rt.set_caller(*CRON_ACTOR_CODE_ID, CRON_ACTOR_ADDR);

        rt.call::<PowerActor>(Method::OnEpochTickEnd as u64, None).unwrap();
        rt.verify();

        // enroll a cron task at epoch 2 (which is in the past)
        let payload = vec![0x01, 0x03];
        h.enroll_cron_event(&rt, 2, &miner_addr, &RawBytes::from(payload.clone())).unwrap();

        // run cron again in the future
        rt.set_epoch(6);
        rt.expect_validate_caller_addr(vec![CRON_ACTOR_ADDR]);
        h.expect_query_network_info(&rt);

        let state: State = rt.get_state();

        let input = DeferredCronEventParams {
            event_payload: payload,
            reward_smoothed: h.this_epoch_reward_smoothed.clone(),
            quality_adj_power_smoothed: state.this_epoch_qa_power_smoothed,
        };
        rt.expect_send_simple(
            miner_addr,
            ON_DEFERRED_CRON_EVENT_METHOD,
            IpldBlock::serialize_cbor(&input).unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::OK,
        );
        rt.expect_send_simple(
            REWARD_ACTOR_ADDR,
            UPDATE_NETWORK_KPI,
            IpldBlock::serialize_cbor(&BigIntSer(&expected_raw_byte_power)).unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::OK,
        );
        rt.set_caller(*CRON_ACTOR_CODE_ID, CRON_ACTOR_ADDR);

        rt.call::<PowerActor>(Method::OnEpochTickEnd as u64, None).unwrap();
        rt.verify();

        // assert used cron events are cleaned up
        let state: State = rt.get_state();

        verify_empty_map(&rt, state.cron_event_queue);
        h.check_state(&rt);
    }

    #[test]
    fn fails_to_enroll_if_epoch_negative() {
        let (mut h, rt) = setup();
        let miner_addr = Address::new_id(101);
        h.create_miner_basic(&rt, OWNER, OWNER, miner_addr).unwrap();

        expect_abort_contains_message(
            ExitCode::USR_ILLEGAL_ARGUMENT,
            "epoch -2 cannot be less than zero",
            h.enroll_cron_event(&rt, -2, &miner_addr, &RawBytes::from(vec![0x01, 0x03])),
        );
        h.check_state(&rt);
    }

    #[test]
    fn skips_invocation_if_miner_has_no_claim() {
        let (mut h, rt) = setup();
        rt.set_epoch(1);

        let miner1 = Address::new_id(101);
        let miner2 = Address::new_id(102);

        h.create_miner_basic(&rt, OWNER, OWNER, miner1).unwrap();
        h.create_miner_basic(&rt, OWNER, OWNER, miner2).unwrap();

        h.enroll_cron_event(&rt, 2, &miner1, &RawBytes::default()).unwrap();
        h.enroll_cron_event(&rt, 2, &miner2, &RawBytes::default()).unwrap();

        // explicitly delete miner 1's claim
        h.delete_claim(&rt, &miner1);

        rt.set_epoch(2);
        rt.expect_validate_caller_addr(vec![CRON_ACTOR_ADDR]);

        // process batch verifies first
        h.expect_query_network_info(&rt);

        let state: State = rt.get_state();
        let input = DeferredCronEventParams {
            event_payload: Vec::new(),
            reward_smoothed: h.this_epoch_reward_smoothed.clone(),
            quality_adj_power_smoothed: state.this_epoch_qa_power_smoothed,
        };

        // only expect second deferred cron event call
        rt.expect_send_simple(
            miner2,
            ON_DEFERRED_CRON_EVENT_METHOD,
            IpldBlock::serialize_cbor(&input).unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::OK,
        );

        // reward actor is still invoked
        rt.expect_send_simple(
            REWARD_ACTOR_ADDR,
            UPDATE_NETWORK_KPI,
            IpldBlock::serialize_cbor(&BigIntSer(&BigInt::zero())).unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::OK,
        );
        rt.set_caller(*CRON_ACTOR_CODE_ID, CRON_ACTOR_ADDR);
        rt.call::<PowerActor>(Method::OnEpochTickEnd as u64, None).unwrap();
        rt.verify();

        h.check_state(&rt);
    }

    #[test]
    fn handles_failed_call() {
        let (mut h, rt) = setup();
        rt.set_epoch(1);

        let miner1 = Address::new_id(101);
        let miner2 = Address::new_id(102);

        h.create_miner_basic(&rt, OWNER, OWNER, miner1).unwrap();
        h.create_miner_basic(&rt, OWNER, OWNER, miner2).unwrap();

        h.enroll_cron_event(&rt, 2, &miner1, &RawBytes::default()).unwrap();
        h.enroll_cron_event(&rt, 2, &miner2, &RawBytes::default()).unwrap();

        let raw_power = consensus_miner_min_power(
            &Policy::default(),
            RegisteredPoStProof::StackedDRGWindow32GiBV1P1,
        )
        .unwrap();

        let qa_power = &raw_power;
        h.update_claimed_power(&rt, miner1, &raw_power, qa_power);
        h.expect_total_power_eager(&rt, &raw_power, qa_power);
        h.expect_miners_above_min_power(&rt, 1);

        rt.set_epoch(2);
        rt.expect_validate_caller_addr(vec![CRON_ACTOR_ADDR]);

        h.expect_query_network_info(&rt);

        let state: State = rt.get_state();
        let input = IpldBlock::serialize_cbor(&DeferredCronEventParams {
            event_payload: Vec::new(),
            reward_smoothed: h.this_epoch_reward_smoothed.clone(),
            quality_adj_power_smoothed: state.this_epoch_qa_power_smoothed,
        })
        .unwrap();

        // first send fails
        rt.expect_send_simple(
            miner1,
            ON_DEFERRED_CRON_EVENT_METHOD,
            input.clone(),
            TokenAmount::zero(),
            None,
            ExitCode::USR_ILLEGAL_STATE,
        );

        // subsequent one still invoked
        rt.expect_send_simple(
            miner2,
            ON_DEFERRED_CRON_EVENT_METHOD,
            input,
            TokenAmount::zero(),
            None,
            ExitCode::OK,
        );
        // reward actor is still invoked
        rt.set_caller(*CRON_ACTOR_CODE_ID, CRON_ACTOR_ADDR);
        rt.expect_send_simple(
            REWARD_ACTOR_ADDR,
            UPDATE_NETWORK_KPI,
            IpldBlock::serialize_cbor(&BigIntSer(&BigInt::zero())).unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::OK,
        );
        rt.call::<PowerActor>(Method::OnEpochTickEnd as u64, None).unwrap();
        rt.verify();

        // expect power stats to be decremented due to claim deletion
        h.expect_total_power_eager(&rt, &BigInt::zero(), &BigInt::zero());
        h.expect_miners_above_min_power(&rt, 0);

        // miner's claim is removed
        assert!(h.get_claim(&rt, &miner1).is_none());

        // miner count has been reduced to 1
        assert_eq!(h.miner_count(&rt), 1);

        // next epoch, only the reward actor is invoked
        rt.set_epoch(3);
        rt.expect_validate_caller_addr(vec![CRON_ACTOR_ADDR]);

        h.expect_query_network_info(&rt);

        rt.expect_send_simple(
            REWARD_ACTOR_ADDR,
            UPDATE_NETWORK_KPI,
            IpldBlock::serialize_cbor(&BigIntSer(&BigInt::zero())).unwrap(),
            TokenAmount::zero(),
            None,
            ExitCode::OK,
        );
        rt.set_caller(*CRON_ACTOR_CODE_ID, CRON_ACTOR_ADDR);

        rt.call::<PowerActor>(Method::OnEpochTickEnd as u64, None).unwrap();
        rt.verify();
        h.check_state(&rt);
    }
}

#[test]
fn create_miner_restricted_correctly() {
    let (h, rt) = setup();

    let peer = "miner".as_bytes().to_vec();
    let multiaddrs = vec![BytesDe("multiaddr".as_bytes().to_vec())];

    let params = IpldBlock::serialize_cbor(&CreateMinerParams {
        owner: *OWNER,
        worker: *OWNER,
        window_post_proof_type: RegisteredPoStProof::StackedDRGWinning2KiBV1,
        peer: peer.clone(),
        multiaddrs: multiaddrs.clone(),
    })
    .unwrap();

    rt.set_caller(*EVM_ACTOR_CODE_ID, *OWNER);

    // cannot call the unexported method
    expect_abort_contains_message(
        ExitCode::USR_FORBIDDEN,
        "must be built-in",
        rt.call::<PowerActor>(Method::CreateMiner as MethodNum, params.clone()),
    );

    // can call the exported method

    rt.expect_validate_caller_any();
    let expected_init_params = ExecParams {
        code_cid: *MINER_ACTOR_CODE_ID,
        constructor_params: RawBytes::serialize(MinerConstructorParams {
            owner: *OWNER,
            worker: *OWNER,
            control_addresses: vec![],
            window_post_proof_type: RegisteredPoStProof::StackedDRGWinning2KiBV1,
            peer_id: peer,
            multi_addresses: multiaddrs,
        })
        .unwrap(),
    };
    let create_miner_ret = CreateMinerReturn { id_address: *MINER, robust_address: *ACTOR };
    rt.expect_send_simple(
        INIT_ACTOR_ADDR,
        EXEC_METHOD,
        IpldBlock::serialize_cbor(&expected_init_params).unwrap(),
        TokenAmount::zero(),
        IpldBlock::serialize_cbor(&create_miner_ret).unwrap(),
        ExitCode::OK,
    );

    let ret: CreateMinerReturn = rt
        .call::<PowerActor>(Method::CreateMinerExported as MethodNum, params)
        .unwrap()
        .unwrap()
        .deserialize()
        .unwrap();
    rt.verify();

    assert_eq!(ret.id_address, *MINER);
    assert_eq!(ret.robust_address, *ACTOR);

    h.check_state(&rt);
}
