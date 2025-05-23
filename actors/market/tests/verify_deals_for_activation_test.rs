// Copyright 2019-2022 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_shared::address::Address;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::piece::PieceInfo;
use fvm_shared::sector::RegisteredSealProof;

use fil_actor_market::{
    ActivatedDeal, Actor as MarketActor, Method, NO_ALLOCATION_ID, SectorDeals,
    VerifyDealsForActivationParams,
};
use fil_actors_runtime::EPOCHS_IN_DAY;
use fil_actors_runtime::runtime::builtins::Type;
use fil_actors_runtime::test_utils::{
    ACCOUNT_ACTOR_CODE_ID, MINER_ACTOR_CODE_ID, expect_abort, expect_abort_contains_message,
    make_piece_cid,
};
use harness::*;

mod harness;
const START_EPOCH: ChainEpoch = 10;
const CURR_EPOCH: ChainEpoch = START_EPOCH;
const END_EPOCH: ChainEpoch = 200 * EPOCHS_IN_DAY;
const SECTOR_EXPIRY: ChainEpoch = END_EPOCH + 200;
const MINER_ADDRESSES: MinerAddresses = MinerAddresses {
    owner: OWNER_ADDR,
    worker: WORKER_ADDR,
    provider: PROVIDER_ADDR,
    control: vec![],
};

#[test]
fn verify_deal_and_activate_to_get_deal_space_for_unverified_deal_proposal() {
    let rt = setup();
    let (deal_id, deal_proposal) =
        generate_and_publish_deal(&rt, CLIENT_ADDR, &MINER_ADDRESSES, START_EPOCH, END_EPOCH);
    let sector_number = 7;

    let v_response = verify_deals_for_activation(
        &rt,
        PROVIDER_ADDR,
        vec![SectorDeals {
            sector_number,
            sector_type: RegisteredSealProof::StackedDRG2KiBV1P1,
            sector_expiry: SECTOR_EXPIRY,
            deal_ids: vec![deal_id],
        }],
        |_| None,
    );
    let a_response =
        activate_deals(&rt, SECTOR_EXPIRY, PROVIDER_ADDR, CURR_EPOCH, sector_number, &[deal_id]);
    let s_response = a_response.activations.first().unwrap();
    assert_eq!(1, v_response.unsealed_cids.len());
    assert_eq!(Some(make_piece_cid("1".as_bytes())), v_response.unsealed_cids[0]);
    assert_eq!(1, s_response.activated.len());
    assert_eq!(
        ActivatedDeal {
            client: CLIENT_ADDR.id().unwrap(),
            allocation_id: NO_ALLOCATION_ID,
            data: deal_proposal.piece_cid,
            size: deal_proposal.piece_size
        },
        *s_response.activated.first().unwrap()
    );

    check_state(&rt);
}

#[test]
fn verify_deal_and_activate_to_get_deal_space_for_verified_deal_proposal() {
    let rt = setup();
    let next_allocation_id = 1;
    let deal_id = generate_and_publish_verified_deal(
        &rt,
        CLIENT_ADDR,
        &MINER_ADDRESSES,
        START_EPOCH,
        END_EPOCH,
        next_allocation_id,
    );
    let deal_proposal = get_deal_proposal(&rt, deal_id);
    let sector_number = 7;
    let response = verify_deals_for_activation(
        &rt,
        PROVIDER_ADDR,
        vec![SectorDeals {
            sector_number,
            sector_type: RegisteredSealProof::StackedDRG2KiBV1P1,
            sector_expiry: SECTOR_EXPIRY,
            deal_ids: vec![deal_id],
        }],
        |_| None,
    );

    let a_response =
        activate_deals(&rt, SECTOR_EXPIRY, PROVIDER_ADDR, CURR_EPOCH, sector_number, &[deal_id]);
    let s_response = a_response.activations.first().unwrap();

    assert_eq!(1, response.unsealed_cids.len());
    assert_eq!(Some(make_piece_cid("1".as_bytes())), response.unsealed_cids[0]);
    assert_eq!(1, s_response.activated.len());
    assert_eq!(deal_proposal.piece_size, s_response.activated[0].size);
    assert_eq!(deal_proposal.client.id().unwrap(), s_response.activated[0].client);
    assert_eq!(deal_proposal.piece_cid, s_response.activated[0].data);
    assert_eq!(next_allocation_id, s_response.activated[0].allocation_id);
    check_state(&rt);
}

#[test]
fn verification_and_weights_for_verified_and_unverified_deals() {
    let rt = setup();
    let create_deal = |end_epoch, verified| {
        create_deal(&rt, CLIENT_ADDR, &MINER_ADDRESSES, START_EPOCH, end_epoch, verified)
    };

    let verified_deal_1 = create_deal(END_EPOCH, true);
    let verified_deal_2 = create_deal(END_EPOCH + 1, true);
    let unverified_deal_1 = create_deal(END_EPOCH + 2, false);
    let unverified_deal_2 = create_deal(END_EPOCH + 3, false);
    let deals = [
        verified_deal_1.clone(),
        verified_deal_2.clone(),
        unverified_deal_1.clone(),
        unverified_deal_2.clone(),
    ];
    let datacap_required =
        TokenAmount::from_whole(verified_deal_1.piece_size.0 + verified_deal_2.piece_size.0);
    rt.set_caller(*ACCOUNT_ACTOR_CODE_ID, WORKER_ADDR);
    let deal_ids = publish_deals(&rt, &MINER_ADDRESSES, &deals, datacap_required, 1);
    assert_eq!(4, deal_ids.len());

    let sector_number = 7;
    verify_deals_for_activation(
        &rt,
        PROVIDER_ADDR,
        vec![SectorDeals {
            sector_number,
            sector_type: RegisteredSealProof::StackedDRG8MiBV1,
            sector_expiry: SECTOR_EXPIRY,
            deal_ids: deal_ids.clone(),
        }],
        |_| {
            Some(
                deals
                    .iter()
                    .map(|deal| PieceInfo { size: deal.piece_size, cid: deal.piece_cid })
                    .collect(),
            )
        },
    );

    let a_response =
        activate_deals(&rt, SECTOR_EXPIRY, PROVIDER_ADDR, CURR_EPOCH, sector_number, &deal_ids);
    let s_response = a_response.activations.first().unwrap();
    assert_eq!(4, s_response.activated.len());
    assert_eq!(
        &ActivatedDeal {
            client: CLIENT_ADDR.id().unwrap(),
            allocation_id: 1,
            data: verified_deal_1.piece_cid,
            size: verified_deal_1.piece_size,
        },
        &s_response.activated[0],
    );
    assert_eq!(
        &ActivatedDeal {
            client: CLIENT_ADDR.id().unwrap(),
            allocation_id: 2,
            data: verified_deal_2.piece_cid,
            size: verified_deal_2.piece_size,
        },
        &s_response.activated[1],
    );
    assert_eq!(
        &ActivatedDeal {
            client: CLIENT_ADDR.id().unwrap(),
            allocation_id: NO_ALLOCATION_ID,
            data: unverified_deal_1.piece_cid,
            size: unverified_deal_1.piece_size,
        },
        &s_response.activated[2],
    );
    assert_eq!(
        &ActivatedDeal {
            client: CLIENT_ADDR.id().unwrap(),
            allocation_id: NO_ALLOCATION_ID,
            data: unverified_deal_2.piece_cid,
            size: unverified_deal_2.piece_size,
        },
        &s_response.activated[3],
    );

    check_state(&rt);
}

#[test]
fn fail_when_caller_is_not_a_storage_miner_actor() {
    let rt = setup();
    let (deal_id, _) =
        generate_and_publish_deal(&rt, CLIENT_ADDR, &MINER_ADDRESSES, START_EPOCH, END_EPOCH);

    rt.set_caller(*ACCOUNT_ACTOR_CODE_ID, WORKER_ADDR);
    rt.expect_validate_caller_type(vec![Type::Miner]);
    let sector_number = 7;
    let params = VerifyDealsForActivationParams {
        sectors: vec![SectorDeals {
            sector_number,
            sector_type: RegisteredSealProof::StackedDRG2KiBV1P1,
            sector_expiry: SECTOR_EXPIRY,
            deal_ids: vec![deal_id],
        }],
    };
    expect_abort(
        ExitCode::USR_FORBIDDEN,
        rt.call::<MarketActor>(
            Method::VerifyDealsForActivation as u64,
            IpldBlock::serialize_cbor(&params).unwrap(),
        ),
    );

    rt.verify();
    check_state(&rt);
}

#[test]
fn fail_when_deal_proposal_is_not_found() {
    let rt = setup();
    let sector_number = 7;
    let params = VerifyDealsForActivationParams {
        sectors: vec![SectorDeals {
            sector_number,
            sector_type: RegisteredSealProof::StackedDRG2KiBV1P1,
            sector_expiry: SECTOR_EXPIRY,
            deal_ids: vec![1],
        }],
    };
    rt.set_caller(*MINER_ACTOR_CODE_ID, PROVIDER_ADDR);
    rt.expect_validate_caller_type(vec![Type::Miner]);
    expect_abort(
        ExitCode::USR_NOT_FOUND,
        rt.call::<MarketActor>(
            Method::VerifyDealsForActivation as u64,
            IpldBlock::serialize_cbor(&params).unwrap(),
        ),
    );

    rt.verify();
    check_state(&rt);
}

#[test]
fn fail_when_caller_is_not_the_provider() {
    let rt = setup();
    let (deal_id, _) =
        generate_and_publish_deal(&rt, CLIENT_ADDR, &MINER_ADDRESSES, START_EPOCH, END_EPOCH);

    rt.set_caller(*MINER_ACTOR_CODE_ID, Address::new_id(205));
    rt.expect_validate_caller_type(vec![Type::Miner]);
    let sector_number = 7;
    let params = VerifyDealsForActivationParams {
        sectors: vec![SectorDeals {
            sector_number,
            sector_type: RegisteredSealProof::StackedDRG2KiBV1P1,
            sector_expiry: SECTOR_EXPIRY,
            deal_ids: vec![deal_id],
        }],
    };
    expect_abort(
        ExitCode::USR_FORBIDDEN,
        rt.call::<MarketActor>(
            Method::VerifyDealsForActivation as u64,
            IpldBlock::serialize_cbor(&params).unwrap(),
        ),
    );

    rt.verify();
    check_state(&rt);
}

#[test]
fn fail_when_current_epoch_is_greater_than_proposal_start_epoch() {
    let rt = setup();
    let (deal_id, _) =
        generate_and_publish_deal(&rt, CLIENT_ADDR, &MINER_ADDRESSES, START_EPOCH, END_EPOCH);
    rt.set_epoch(START_EPOCH + 1);

    rt.set_caller(*MINER_ACTOR_CODE_ID, PROVIDER_ADDR);
    rt.expect_validate_caller_type(vec![Type::Miner]);
    let sector_number = 7;
    let params = VerifyDealsForActivationParams {
        sectors: vec![SectorDeals {
            sector_number,
            sector_type: RegisteredSealProof::StackedDRG2KiBV1P1,
            sector_expiry: SECTOR_EXPIRY,
            deal_ids: vec![deal_id],
        }],
    };
    expect_abort(
        fil_actor_market::EX_DEAL_EXPIRED,
        rt.call::<MarketActor>(
            Method::VerifyDealsForActivation as u64,
            IpldBlock::serialize_cbor(&params).unwrap(),
        ),
    );

    rt.verify();
    check_state(&rt);
}

#[test]
fn fail_when_deal_end_epoch_is_greater_than_sector_expiration() {
    let rt = setup();
    let (deal_id, _) =
        generate_and_publish_deal(&rt, CLIENT_ADDR, &MINER_ADDRESSES, START_EPOCH, END_EPOCH);

    rt.set_caller(*MINER_ACTOR_CODE_ID, PROVIDER_ADDR);
    rt.expect_validate_caller_type(vec![Type::Miner]);
    let sector_number = 7;
    let params = VerifyDealsForActivationParams {
        sectors: vec![SectorDeals {
            sector_number,
            sector_type: RegisteredSealProof::StackedDRG2KiBV1P1,
            sector_expiry: END_EPOCH - 1,
            deal_ids: vec![deal_id],
        }],
    };
    expect_abort(
        ExitCode::USR_ILLEGAL_ARGUMENT,
        rt.call::<MarketActor>(
            Method::VerifyDealsForActivation as u64,
            IpldBlock::serialize_cbor(&params).unwrap(),
        ),
    );

    rt.verify();
    check_state(&rt);
}

#[test]
fn fail_when_the_same_deal_id_is_passed_multiple_times() {
    let rt = setup();
    let (deal_id, _) =
        generate_and_publish_deal(&rt, CLIENT_ADDR, &MINER_ADDRESSES, START_EPOCH, END_EPOCH);

    rt.set_caller(*MINER_ACTOR_CODE_ID, PROVIDER_ADDR);
    rt.expect_validate_caller_type(vec![Type::Miner]);
    let sector_number = 7;
    let params = VerifyDealsForActivationParams {
        sectors: vec![SectorDeals {
            sector_number,
            sector_type: RegisteredSealProof::StackedDRG8MiBV1,
            sector_expiry: SECTOR_EXPIRY,
            deal_ids: vec![deal_id, deal_id],
        }],
    };
    expect_abort_contains_message(
        ExitCode::USR_ILLEGAL_ARGUMENT,
        "duplicate deal",
        rt.call::<MarketActor>(
            Method::VerifyDealsForActivation as u64,
            IpldBlock::serialize_cbor(&params).unwrap(),
        ),
    );

    rt.verify();
    check_state(&rt);
}
