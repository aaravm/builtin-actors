use fil_actor_market::ActivatedDeal;
use fil_actor_miner::ext::verifreg::Claim as FILPlusClaim;
use fil_actor_miner::{
    ExpirationExtension, ExpirationExtension2, ExtendSectorExpiration2Params,
    ExtendSectorExpirationParams, PoStPartition, SectorClaim, SectorOnChainInfo, State,
    daily_proof_fee, power_for_sector, seal_proof_sector_maximum_lifetime,
};
use fil_actors_runtime::DealWeight;
use fil_actors_runtime::{
    EPOCHS_IN_DAY, actor_error,
    runtime::{Runtime, RuntimePolicy},
    test_utils::{MockRuntime, expect_abort_contains_message, make_piece_cid},
};
use fvm_ipld_bitfield::BitField;
use fvm_shared::bigint::BigInt;
use fvm_shared::deal::DealID;
use fvm_shared::econ::TokenAmount;
use fvm_shared::piece::PaddedPieceSize;
use fvm_shared::version::NetworkVersion;
use fvm_shared::{
    ActorID,
    address::Address,
    clock::ChainEpoch,
    error::ExitCode,
    sector::{RegisteredSealProof, SectorNumber},
};

use num_traits::Zero;
use std::collections::HashMap;

mod util;

use fil_actors_runtime::runtime::Policy;
use itertools::Itertools;
use test_case::test_case;
use util::*;

// an expiration ~10 days greater than effective min expiration taking into account 30 days max between pre and prove commit
const DEFAULT_SECTOR_EXPIRATION: ChainEpoch = 220;

fn setup() -> (ActorHarness, MockRuntime) {
    let period_offset = 100;
    let precommit_epoch = 1;

    let mut h = ActorHarness::new(period_offset);
    // reduce the partition size
    // if changed to V1P1 the rejects_extension_past_max_for_seal_proof test fails
    h.set_proof_type(RegisteredSealProof::StackedDRG512MiBV1);
    let rt = h.new_runtime();
    rt.balance.replace(BIG_BALANCE.clone());
    rt.set_epoch(precommit_epoch);

    (h, rt)
}

fn commit_sector(h: &mut ActorHarness, rt: &MockRuntime) -> SectorOnChainInfo {
    h.construct_and_verify(rt);

    h.commit_and_prove_sectors(rt, 1, DEFAULT_SECTOR_EXPIRATION as u64, Vec::new(), true)[0]
        .to_owned()
}

#[test_case(false; "v1")]
#[test_case(true; "v2")]
fn rejects_negative_extensions(v2: bool) {
    let (mut h, rt) = setup();
    let sector = commit_sector(&mut h, &rt);

    // attempt to shorten epoch
    let new_expiration = sector.expiration - rt.policy().wpost_proving_period;

    // find deadline and partition
    let state: State = rt.get_state();
    let (deadline_index, partition_index) =
        state.find_sector(rt.store(), sector.sector_number).unwrap();

    let params = ExtendSectorExpirationParams {
        extensions: vec![ExpirationExtension {
            deadline: deadline_index,
            partition: partition_index,
            sectors: make_bitfield(&[sector.sector_number]),
            new_expiration,
        }],
    };

    let res = h.extend_sectors_versioned(&rt, params, v2);
    expect_abort_contains_message(
        ExitCode::USR_ILLEGAL_ARGUMENT,
        &format!("cannot reduce sector {} expiration", sector.sector_number),
        res,
    );
    h.check_state(&rt);
}

#[test_case(false; "v1")]
#[test_case(true; "v2")]
fn rejects_extension_too_far_in_future(v2: bool) {
    let (mut h, rt) = setup();
    let sector = commit_sector(&mut h, &rt);

    // extend by even proving period after max
    rt.set_epoch(sector.expiration);
    let extension = rt.policy().wpost_proving_period + rt.policy().max_sector_expiration_extension;
    let new_expiration = *rt.epoch.borrow() + extension;

    // find deadline and partition
    let state: State = rt.get_state();
    let (deadline_index, partition_index) =
        state.find_sector(rt.store(), sector.sector_number).unwrap();

    let params = ExtendSectorExpirationParams {
        extensions: vec![ExpirationExtension {
            deadline: deadline_index,
            partition: partition_index,
            sectors: make_bitfield(&[sector.sector_number]),
            new_expiration,
        }],
    };

    let res = h.extend_sectors_versioned(&rt, params, v2);
    expect_abort_contains_message(
        ExitCode::USR_ILLEGAL_ARGUMENT,
        &format!(
            "cannot be more than {} past current epoch",
            rt.policy().max_sector_expiration_extension
        ),
        res,
    );
    h.check_state(&rt);
}

#[test_case(false; "v1")]
#[test_case(true; "v2")]
fn rejects_extension_past_max_for_seal_proof(v2: bool) {
    let (mut h, rt) = setup();
    let mut sector = commit_sector(&mut h, &rt);
    // and prove it once to activate it.
    h.advance_and_submit_posts(&rt, &vec![sector.clone()]);

    let max_lifetime = seal_proof_sector_maximum_lifetime(sector.seal_proof).unwrap();

    let state: State = rt.get_state();
    let (deadline_index, partition_index) =
        state.find_sector(rt.store(), sector.sector_number).unwrap();

    // extend sector until just below threshold
    rt.set_epoch(sector.expiration);
    let extension = rt.policy().min_sector_expiration;

    let mut expiration = sector.expiration + extension;
    while expiration - sector.activation < max_lifetime {
        let params = ExtendSectorExpirationParams {
            extensions: vec![ExpirationExtension {
                deadline: deadline_index,
                partition: partition_index,
                sectors: make_bitfield(&[sector.sector_number]),
                new_expiration: expiration,
            }],
        };
        h.extend_sectors(&rt, params).unwrap();
        sector.expiration = expiration;

        expiration += extension;
    }

    // next extension fails because it extends sector past max lifetime
    let params = ExtendSectorExpirationParams {
        extensions: vec![ExpirationExtension {
            deadline: deadline_index,
            partition: partition_index,
            sectors: make_bitfield(&[sector.sector_number]),
            new_expiration: expiration,
        }],
    };

    let res = h.extend_sectors_versioned(&rt, params, v2);
    expect_abort_contains_message(ExitCode::USR_ILLEGAL_ARGUMENT, "total sector lifetime", res);
    h.check_state(&rt);
}

#[test_case(false; "v1")]
#[test_case(true; "v2")]
fn updates_expiration_with_valid_params(v2: bool) {
    let (mut h, rt) = setup();

    let old_sector = commit_sector(&mut h, &rt);
    h.advance_and_submit_posts(&rt, &vec![old_sector.clone()]);

    let state: State = rt.get_state();

    let (deadline_index, partition_index) =
        state.find_sector(rt.store(), old_sector.sector_number).unwrap();

    let extension = 42 * rt.policy().wpost_proving_period;
    let new_expiration = old_sector.expiration + extension;

    let params = ExtendSectorExpirationParams {
        extensions: vec![ExpirationExtension {
            deadline: deadline_index,
            partition: partition_index,
            sectors: make_bitfield(&[old_sector.sector_number]),
            new_expiration,
        }],
    };

    // Change the circulating supply so we can detect fee changes (that shouldn't happen).
    rt.set_circulating_supply(rt.total_fil_circ_supply() * 2);

    h.extend_sectors_versioned(&rt, params, v2).unwrap();

    // assert sector expiration is set to the new value
    let new_sector = h.get_sector(&rt, old_sector.sector_number);
    assert_eq!(new_expiration, new_sector.expiration);

    // assert that the fee hasn't changed
    assert_eq!(old_sector.daily_fee, new_sector.daily_fee);
    let deadline = h.get_deadline(&rt, deadline_index);
    assert_eq!(new_sector.daily_fee, deadline.daily_fee);

    let quant = state.quant_spec_for_deadline(rt.policy(), deadline_index);

    // assert that new expiration exists
    let (_, mut partition) = h.get_deadline_and_partition(&rt, deadline_index, partition_index);
    let expiration_set =
        partition.pop_expired_sectors(rt.store(), new_expiration - 1, quant).unwrap();
    assert!(expiration_set.is_empty());

    let expiration_set = partition
        .pop_expired_sectors(rt.store(), quant.quantize_up(new_expiration), quant)
        .unwrap();
    assert_eq!(expiration_set.len(), 1);
    assert!(expiration_set.on_time_sectors.get(old_sector.sector_number));

    h.check_state(&rt);
}

#[test_case(false, 25; "v1_grace")]
#[test_case(false, 26; "v1_active")]
#[test_case(true, 25; "v2_grace")]
#[test_case(true, 26; "v2_active")]
fn updates_expiration_and_daily_fee(v2: bool, nv: u32) {
    // Start with sectors that have a zero fee (i.e. indicating they are pre-FIP-0100). Two sectors
    // for both cases, but in v2 we will make the second sector fully verified to test the fee
    // calculation.

    let (mut h, rt) = setup();

    // Common setup
    h.construct_and_verify(&rt);
    rt.set_circulating_supply(TokenAmount::zero());
    rt.set_network_version(NetworkVersion::from(nv));

    // Create deal for v2 cases
    let deal = ActivatedDeal {
        client: 0,
        allocation_id: 1,
        data: Default::default(),
        size: PaddedPieceSize(h.sector_size as u64),
    };

    // Configure sectors based on version
    let sector_pieces = vec![vec![], if v2 { vec![1] } else { vec![] }];
    let activated_deals =
        if v2 { HashMap::from_iter(vec![(1, vec![deal.clone()])]) } else { Default::default() };
    // Commit sectors
    let config = ProveCommitConfig {
        verify_deals_exit: Default::default(),
        claim_allocs_exit: Default::default(),
        activated_deals,
    };

    let old_sectors = h.commit_and_prove_sectors_with_cfgs(
        &rt,
        2,
        DEFAULT_SECTOR_EXPIRATION as u64,
        sector_pieces,
        true,
        config,
    );
    h.advance_and_submit_posts(&rt, &old_sectors);

    // Verify initial state (fees should be zero)
    for sector in &old_sectors {
        assert_eq!(
            sector.daily_fee,
            TokenAmount::zero(),
            "expected sector's daily fee to be zero because the circulating supply is zero"
        );
    }
    h.advance_and_submit_posts(&rt, &old_sectors);

    // Prepare extension parameters
    let state: State = rt.get_state();
    let (deadline_index, partition_index) =
        state.find_sector(rt.store(), old_sectors[0].sector_number).unwrap();
    let extension = 42 * rt.policy().wpost_proving_period;
    let new_expiration = old_sectors[0].expiration + extension;

    assert!(h.get_deadline(&rt, deadline_index).daily_fee.is_zero());

    // Set circulating supply to trigger fee calculation
    let new_circulating_supply = TokenAmount::from_whole(500_000_000);
    rt.set_circulating_supply(new_circulating_supply.clone());

    // Extend sectors using version-appropriate method
    if v2 {
        // v2: separate regular sectors and sectors with claims
        let params = ExtendSectorExpiration2Params {
            extensions: vec![ExpirationExtension2 {
                deadline: deadline_index,
                partition: partition_index,
                sectors: make_bitfield(&[old_sectors[0].sector_number]),
                sectors_with_claims: vec![SectorClaim {
                    sector_number: old_sectors[1].sector_number,
                    maintain_claims: vec![1],
                    drop_claims: vec![],
                }],
                new_expiration,
            }],
        };

        // Create claim for v2
        let client = Address::new_id(3000).id().unwrap();
        let claim = make_claim(
            1,
            &old_sectors[1],
            client,
            h.receiver.id().unwrap(),
            new_expiration,
            &deal,
            rt.policy.minimum_verified_allocation_term,
        );

        let mut claims = HashMap::new();
        claims.insert(1, Ok(claim));

        h.extend_sectors2(&rt, params, claims).unwrap();
    } else {
        // v1: extend all sectors together
        let params = ExtendSectorExpirationParams {
            extensions: vec![ExpirationExtension {
                deadline: deadline_index,
                partition: partition_index,
                sectors: make_bitfield(
                    old_sectors.iter().map(|s| s.sector_number).collect_vec().as_slice(),
                ),
                new_expiration,
            }],
        };
        h.extend_sectors(&rt, params).unwrap();
    }

    let new_sectors = old_sectors.iter().map(|s| h.get_sector(&rt, s.sector_number)).collect_vec();

    // Verify expirations
    for sector in &new_sectors {
        assert_eq!(new_expiration, sector.expiration);
    }

    // Calculate expected fee for a full verified sector and the total fee of our two sectors
    // combined, taking into account the grace period during which fees are zero.
    let (full_verified_fee, total_fee) = if nv >= 26 {
        (
            daily_proof_fee(
                &rt.policy,
                &rt.circulating_supply.borrow(),
                &BigInt::from(h.sector_size as u64 * 10),
            ),
            new_sectors[0].daily_fee.clone() + new_sectors[1].daily_fee.clone(),
        )
    } else {
        (TokenAmount::zero(), TokenAmount::zero()) // grace period
    };

    // Verify fees - first sector has divided fee in both versions
    assert_eq!(full_verified_fee.div_floor(10), new_sectors[0].daily_fee);
    // Second sector fee depends on version
    let expected_fee = if v2 { full_verified_fee } else { full_verified_fee.div_floor(10) };
    assert_eq!(expected_fee, new_sectors[1].daily_fee);

    let (deadline, partition) = h.get_deadline_and_partition(&rt, deadline_index, partition_index);
    // Deadline has the two fees
    assert_eq!(total_fee, deadline.daily_fee);

    // Partition expiration queue has the total fee as a deduction
    let quant = h.get_state(&rt).quant_spec_for_deadline(&rt.policy, deadline_index);
    let quantized_expiration = quant.quantize_up(new_sectors[0].expiration);
    let p_queue = h.collect_partition_expirations(&rt, &partition);
    let entry = p_queue.get(&quantized_expiration).cloned().unwrap();
    assert_eq!(total_fee, entry.fee_deduction);

    h.check_state(&rt);
}

#[test_case(false; "v1")]
#[test_case(true; "v2")]
fn updates_many_sectors(v2: bool) {
    let (mut h, rt) = setup();
    h.construct_and_verify(&rt);

    let sector_count = 4;

    // commit a bunch of sectors to ensure that we get multiple partitions
    let sector_infos = h.commit_and_prove_sectors(
        &rt,
        sector_count as usize,
        DEFAULT_SECTOR_EXPIRATION as u64,
        Vec::new(),
        true,
    );
    h.advance_and_submit_posts(&rt, &sector_infos);

    let new_expiration = sector_infos[0].expiration + 42 * rt.policy().wpost_proving_period;
    let mut extensions: Vec<ExpirationExtension> = Vec::new();

    let state: State = rt.get_state();
    let deadlines = state.load_deadlines(rt.store()).unwrap();
    deadlines
        .for_each(rt.store(), |deadline_index, deadline| {
            let partitions = deadline.partitions_amt(rt.store()).unwrap();
            partitions
                .for_each(|partition_index, partition| {
                    // filter out even-numbered sectors
                    let sectors = partition
                        .sectors
                        .bounded_iter(rt.policy().addressed_sectors_max)
                        .unwrap()
                        .filter(|n| n % 2 != 0)
                        .collect_vec();

                    extensions.push(ExpirationExtension {
                        deadline: deadline_index,
                        partition: partition_index,
                        sectors: make_bitfield(&sectors),
                        new_expiration,
                    });

                    Ok(())
                })
                .unwrap();
            Ok(())
        })
        .unwrap();

    // make sure we're touching at least two partitions
    assert!(extensions.len() >= 2, "test error: this test should touch more than one partition");
    let params = ExtendSectorExpirationParams { extensions };

    h.extend_sectors_versioned(&rt, params, v2).unwrap();
    let state: State = rt.get_state();
    let deadlines = state.load_deadlines(rt.store()).unwrap();

    // half of the sectors should expire on-time
    let (mut on_time_total, mut extended_total) = (0, 0);
    deadlines
        .for_each(rt.store(), |deadline_index, mut deadline| {
            let expiration_set = deadline
                .pop_expired_sectors(
                    rt.store(),
                    new_expiration - 1,
                    state.quant_spec_for_deadline(rt.policy(), deadline_index),
                )
                .unwrap();
            on_time_total += expiration_set.len();

            // ensure we pop queue up to the deadline-specific expiration
            let quant = state.quant_spec_for_deadline(rt.policy(), deadline_index);
            let expiration_set = deadline
                .pop_expired_sectors(rt.store(), quant.quantize_up(new_expiration), quant)
                .unwrap();
            extended_total += expiration_set.len();
            Ok(())
        })
        .unwrap();
    assert_eq!(sector_count / 2, on_time_total);
    assert_eq!(sector_count / 2, extended_total);

    h.check_state(&rt);
}

#[test_case(false; "v1")]
#[test_case(true; "v2")]
fn supports_extensions_off_deadline_boundary(v2: bool) {
    let (mut h, rt) = setup();
    let old_sector = commit_sector(&mut h, &rt);
    h.advance_and_submit_posts(&rt, &vec![old_sector.clone()]);

    let state: State = rt.get_state();
    let (deadline_index, partition_index) =
        state.find_sector(rt.store(), old_sector.sector_number).unwrap();

    let extension = 42 * rt.policy().wpost_proving_period + rt.policy().wpost_proving_period / 3;
    let new_expiration = old_sector.expiration + extension;

    let params = ExtendSectorExpirationParams {
        extensions: vec![ExpirationExtension {
            deadline: deadline_index,
            partition: partition_index,
            sectors: make_bitfield(&[old_sector.sector_number]),
            new_expiration,
        }],
    };

    h.extend_sectors_versioned(&rt, params, v2).unwrap();

    // assert sector expiration is set to the new value
    let mut state: State = rt.get_state();
    let new_sector = h.get_sector(&rt, old_sector.sector_number);
    assert_eq!(new_expiration, new_sector.expiration);

    // advance clock to expiration
    rt.set_epoch(new_sector.expiration);
    state.proving_period_start += rt.policy().wpost_proving_period
        * ((*rt.epoch.borrow() - state.proving_period_start) / rt.policy().wpost_proving_period
            + 1);
    rt.replace_state(&state);

    // confirm it is not in sector's deadline to make sure we're testing extensions off the deadline boundary"
    let deadline_info = h.deadline(&rt);
    assert_ne!(deadline_index, deadline_info.index);

    // advance to deadline and submit one last PoSt
    let deadline_info = h.advance_to_deadline(&rt, deadline_index);

    let partitions = vec![PoStPartition { index: partition_index, skipped: BitField::default() }];
    h.submit_window_post(
        &rt,
        &deadline_info,
        partitions,
        vec![new_sector.clone()],
        PoStConfig::empty(),
    );

    // advance one more time. No missed PoSt fees are charged. Total power and pledge are lowered.
    let power = -power_for_sector(h.sector_size, &new_sector);
    let mut cron_config = CronConfig::empty();
    cron_config.no_enrollment = true;
    cron_config.power_delta = Some(power);
    cron_config.pledge_delta = -new_sector.initial_pledge;

    h.advance_deadline(&rt, cron_config);

    let state: State = rt.get_state();
    assert!(!state.deadline_cron_active);

    h.check_state(&rt);
}

#[test]
fn update_expiration2_multiple_claims() {
    let (mut h, rt) = setup();
    // add in verified deal
    let verified_deals = vec![
        test_activated_deal(h.sector_size as u64 / 2, 1),
        test_activated_deal(h.sector_size as u64 / 2, 2),
    ];
    let old_sector = commit_sector_verified_deals(&verified_deals, &mut h, &rt);
    h.advance_and_submit_posts(&rt, &vec![old_sector.clone()]);

    let state: State = rt.get_state();

    let (deadline_index, partition_index) =
        state.find_sector(rt.store(), old_sector.sector_number).unwrap();

    let extension = 42 * rt.policy().wpost_proving_period;
    let new_expiration = old_sector.expiration + extension;

    let claim_ids = vec![400, 500];
    let client = Address::new_id(3000).id().unwrap();

    let claim0 = make_claim(
        claim_ids[0],
        &old_sector,
        client,
        h.receiver.id().unwrap(),
        new_expiration,
        &verified_deals[0],
        rt.policy.minimum_verified_allocation_term,
    );
    let claim1 = make_claim(
        claim_ids[1],
        &old_sector,
        client,
        h.receiver.id().unwrap(),
        new_expiration,
        &verified_deals[1],
        rt.policy.minimum_verified_allocation_term,
    );

    let mut claims = HashMap::new();
    claims.insert(claim_ids[0], Ok(claim0));
    claims.insert(claim_ids[1], Ok(claim1));

    let params = ExtendSectorExpiration2Params {
        extensions: vec![ExpirationExtension2 {
            deadline: deadline_index,
            partition: partition_index,
            sectors: BitField::new(),
            new_expiration,
            sectors_with_claims: vec![SectorClaim {
                sector_number: old_sector.sector_number,
                maintain_claims: claim_ids,
                drop_claims: vec![],
            }],
        }],
    };

    h.extend_sectors2(&rt, params, claims).unwrap();

    // assert sector expiration is set to the new value
    check_for_expiration(
        &mut h,
        &rt,
        new_expiration,
        old_sector.sector_number,
        deadline_index,
        partition_index,
    );

    // fee should not have changed
    let new_sector = h.get_sector(&rt, old_sector.sector_number);
    assert_eq!(old_sector.daily_fee, new_sector.daily_fee);

    let (deadline, partition) = h.get_deadline_and_partition(&rt, deadline_index, partition_index);

    // deadline has the fee
    assert_eq!(new_sector.daily_fee, deadline.daily_fee);

    // partition expiration queue has the fee as a deduction
    let quant = h.get_state(&rt).quant_spec_for_deadline(&rt.policy, deadline_index);
    let quantized_expiration = quant.quantize_up(new_sector.expiration);
    let p_queue = h.collect_partition_expirations(&rt, &partition);
    let entry = p_queue.get(&quantized_expiration).cloned().unwrap();
    assert_eq!(new_sector.daily_fee, entry.fee_deduction);
}

#[test]
fn update_expiration2_failure_cases() {
    let (mut h, rt) = setup();
    // add in verified deal
    let verified_deals = vec![
        test_activated_deal(h.sector_size as u64 / 2, 1),
        test_activated_deal(h.sector_size as u64 / 2, 2),
    ];
    let old_sector = commit_sector_verified_deals(&verified_deals, &mut h, &rt);
    h.advance_and_submit_posts(&rt, &vec![old_sector.clone()]);

    let state: State = rt.get_state();

    let (deadline_index, partition_index) =
        state.find_sector(rt.store(), old_sector.sector_number).unwrap();

    let extension = 42 * rt.policy().wpost_proving_period;
    let new_expiration = old_sector.expiration + extension;

    let claim_ids = vec![400, 500];
    let client = Address::new_id(3000).id().unwrap();

    let claim0 = make_claim(
        claim_ids[0],
        &old_sector,
        client,
        h.receiver.id().unwrap(),
        new_expiration,
        &verified_deals[0],
        rt.policy.minimum_verified_allocation_term,
    );
    let mut claim1 = make_claim(
        claim_ids[1],
        &old_sector,
        client,
        h.receiver.id().unwrap(),
        new_expiration,
        &verified_deals[1],
        rt.policy.minimum_verified_allocation_term,
    );

    /* 1. Claim used by sector not referenced in extension params */
    {
        let mut claims = HashMap::new();
        claims.insert(claim_ids[0], Ok(claim0.clone()));

        let params = ExtendSectorExpiration2Params {
            extensions: vec![ExpirationExtension2 {
                deadline: deadline_index,
                partition: partition_index,
                sectors: BitField::new(),
                new_expiration,
                sectors_with_claims: vec![SectorClaim {
                    sector_number: old_sector.sector_number,
                    maintain_claims: vec![claim_ids[0]],
                    drop_claims: vec![],
                }],
            }],
        };

        let res = h.extend_sectors2(&rt, params, claims);
        expect_abort_contains_message(
            ExitCode::USR_ILLEGAL_ARGUMENT,
            "does not match verified deal space",
            res,
        );
        // assert sector expiration is same as the old value
        check_for_expiration(
            &mut h,
            &rt,
            old_sector.expiration,
            old_sector.sector_number,
            deadline_index,
            partition_index,
        );
        rt.replace_state(&state);
        rt.reset();
    }

    /* Claim not found */
    {
        let mut claims = HashMap::new();
        claims.insert(claim_ids[0], Ok(claim0.clone()));
        claims.insert(claim_ids[1], Err(actor_error!(not_found, "claim not found")));

        let params = ExtendSectorExpiration2Params {
            extensions: vec![ExpirationExtension2 {
                deadline: deadline_index,
                partition: partition_index,
                sectors: BitField::new(),
                new_expiration,
                sectors_with_claims: vec![SectorClaim {
                    sector_number: old_sector.sector_number,
                    maintain_claims: claim_ids.clone(),
                    drop_claims: vec![],
                }],
            }],
        };

        let res = h.extend_sectors2(&rt, params, claims);
        expect_abort_contains_message(
            ExitCode::USR_ILLEGAL_ARGUMENT,
            "failed to get claims for sector",
            res,
        );
        // assert sector expiration is set to the new value
        check_for_expiration(
            &mut h,
            &rt,
            old_sector.expiration,
            old_sector.sector_number,
            deadline_index,
            partition_index,
        );
        rt.replace_state(&state);
        rt.reset();
    }
    /* Bad claim -- max term too small for expiration */
    {
        claim1.term_max -= 1;
        let mut claims = HashMap::new();
        claims.insert(claim_ids[0], Ok(claim0));
        claims.insert(claim_ids[1], Ok(claim1));

        let params = ExtendSectorExpiration2Params {
            extensions: vec![ExpirationExtension2 {
                deadline: deadline_index,
                partition: partition_index,
                sectors: BitField::new(),
                new_expiration,
                sectors_with_claims: vec![SectorClaim {
                    sector_number: old_sector.sector_number,
                    maintain_claims: claim_ids,
                    drop_claims: vec![],
                }],
            }],
        };

        let res = h.extend_sectors2(&rt, params, claims);
        expect_abort_contains_message(
            ExitCode::USR_FORBIDDEN,
            &format!(
                "claim only allows extension to {} but declared new expiration is {}",
                new_expiration - 1,
                new_expiration
            ),
            res,
        );
        // assert sector expiration is set to the new value
        check_for_expiration(
            &mut h,
            &rt,
            old_sector.expiration,
            old_sector.sector_number,
            deadline_index,
            partition_index,
        );
        rt.replace_state(&state);
        rt.reset();
    }
}

#[test]
fn extend_expiration2_drop_claims() {
    let (mut h, rt) = setup();
    // add in verified deal
    let verified_deals = vec![
        test_activated_deal(h.sector_size as u64 / 2, 1),
        test_activated_deal(h.sector_size as u64 / 2, 2),
    ];
    let policy = Policy::default();
    let old_sector = commit_sector_verified_deals(&verified_deals, &mut h, &rt);
    let state: State = rt.get_state();
    let (deadline_index, partition_index) =
        state.find_sector(rt.store(), old_sector.sector_number).unwrap();

    {
        // sanity check deadline and partition state is correct for original sector's fees
        let (deadline, partition) =
            h.get_deadline_and_partition(&rt, deadline_index, partition_index);

        // deadline has the fee
        assert_eq!(old_sector.daily_fee, deadline.daily_fee);

        // partition expiration queue has the fee as a deduction
        let quant = h.get_state(&rt).quant_spec_for_deadline(&rt.policy, deadline_index);
        let quantized_expiration = quant.quantize_up(old_sector.expiration);
        let p_queue = h.collect_partition_expirations(&rt, &partition);
        let entry = p_queue.get(&quantized_expiration).cloned().unwrap();
        assert_eq!(old_sector.daily_fee, entry.fee_deduction);
    }

    h.advance_and_submit_posts(&rt, &vec![old_sector.clone()]);

    let extension = 42 * rt.policy().wpost_proving_period;
    let new_expiration = old_sector.expiration + extension;

    let claim_ids = [400, 500];
    let client = Address::new_id(3000).id().unwrap();
    let second_expiration = new_expiration + 42 * EPOCHS_IN_DAY;

    let claim0 = make_claim(
        claim_ids[0],
        &old_sector,
        client,
        h.receiver.id().unwrap(),
        second_expiration,
        &verified_deals[0],
        rt.policy.minimum_verified_allocation_term,
    );
    let claim1 = make_claim(
        claim_ids[1],
        &old_sector,
        client,
        h.receiver.id().unwrap(),
        new_expiration,
        &verified_deals[1],
        rt.policy.minimum_verified_allocation_term,
    );
    let mut claims = HashMap::new();
    claims.insert(claim_ids[0], Ok(claim0.clone()));
    claims.insert(claim_ids[1], Ok(claim1));

    let params = ExtendSectorExpiration2Params {
        extensions: vec![ExpirationExtension2 {
            deadline: deadline_index,
            partition: partition_index,
            sectors: BitField::new(),
            new_expiration,
            sectors_with_claims: vec![SectorClaim {
                sector_number: old_sector.sector_number,
                maintain_claims: vec![claim_ids[0]],
                drop_claims: vec![claim_ids[1]],
            }],
        }],
    };
    rt.set_epoch(old_sector.expiration - policy.end_of_life_claim_drop_period);
    h.extend_sectors2(&rt, params, claims).unwrap();
    check_for_expiration(
        &mut h,
        &rt,
        new_expiration,
        old_sector.sector_number,
        deadline_index,
        partition_index,
    );

    assert_sector_verified_space(&mut h, &rt, old_sector.sector_number, verified_deals[0].size.0);

    let new_sector = h.get_sector(&rt, old_sector.sector_number);

    {
        // after dropping a claim that occupies half of the sector the daily fee should go down to the
        // fee of a half verified sector
        let expected_new_fee = (old_sector.daily_fee * 11).div_floor(20);
        assert_eq!(expected_new_fee, new_sector.daily_fee);
        let deadline = h.get_deadline(&rt, deadline_index);
        assert_eq!(expected_new_fee, deadline.daily_fee);
    }

    {
        // check the deadline and partition state is correct for the replaced sector's fee
        let (deadline, partition) =
            h.get_deadline_and_partition(&rt, deadline_index, partition_index);

        // deadline has the fee
        assert_eq!(new_sector.daily_fee, deadline.daily_fee);

        // partition expiration queue has the fee as a deduction
        let quant = h.get_state(&rt).quant_spec_for_deadline(&rt.policy, deadline_index);
        let quantized_expiration = quant.quantize_up(new_sector.expiration);
        let p_queue = h.collect_partition_expirations(&rt, &partition);
        let entry = p_queue.get(&quantized_expiration).cloned().unwrap();
        assert_eq!(new_sector.daily_fee, entry.fee_deduction);
    }

    // only claim0 stored in verifreg now
    let mut claims = HashMap::new();
    claims.insert(claim_ids[0], Ok(claim0));

    // attempting to extend without accounting for claim0 fails
    let bad_params2 = ExtendSectorExpiration2Params {
        extensions: vec![ExpirationExtension2 {
            deadline: deadline_index,
            partition: partition_index,
            sectors: bitfield_from_slice(&[old_sector.sector_number]),
            new_expiration: second_expiration,
            sectors_with_claims: vec![],
        }],
    };
    expect_abort_contains_message(
        ExitCode::USR_ILLEGAL_ARGUMENT,
        "claim missing from declaration for sector",
        h.extend_sectors2(&rt, bad_params2, claims.clone()),
    );
    rt.reset();

    // if we extend again the dropped claim is irrelevant
    let params2 = ExtendSectorExpiration2Params {
        extensions: vec![ExpirationExtension2 {
            deadline: deadline_index,
            partition: partition_index,
            sectors: BitField::new(),
            new_expiration: second_expiration,
            sectors_with_claims: vec![SectorClaim {
                sector_number: old_sector.sector_number,
                maintain_claims: vec![claim_ids[0]],
                drop_claims: vec![],
            }],
        }],
    };
    h.extend_sectors2(&rt, params2, claims).unwrap();
    check_for_expiration(
        &mut h,
        &rt,
        second_expiration,
        old_sector.sector_number,
        deadline_index,
        partition_index,
    );

    assert_sector_verified_space(&mut h, &rt, old_sector.sector_number, verified_deals[0].size.0);
}

#[test]
fn update_expiration_legacy_fails_on_new_sector_with_deals() {
    let (mut h, rt) = setup();
    // add in verified deal
    let verified_deals = vec![
        test_activated_deal(h.sector_size as u64 / 2, 1),
        test_activated_deal(h.sector_size as u64 / 2, 2),
    ];
    let old_sector = commit_sector_verified_deals(&verified_deals, &mut h, &rt);
    h.advance_and_submit_posts(&rt, &vec![old_sector.clone()]);

    let state: State = rt.get_state();

    let (deadline_index, partition_index) =
        state.find_sector(rt.store(), old_sector.sector_number).unwrap();

    let extension = 42 * rt.policy().wpost_proving_period;
    let new_expiration = old_sector.expiration + extension;

    let params = ExtendSectorExpirationParams {
        extensions: vec![ExpirationExtension {
            deadline: deadline_index,
            partition: partition_index,
            sectors: make_bitfield(&[old_sector.sector_number]),
            new_expiration,
        }],
    };

    // legacy extend_sectors will fail to extend newly created sectors with deals
    expect_abort_contains_message(
        ExitCode::USR_FORBIDDEN,
        "cannot use legacy sector extension for simple qa power with deal weight",
        h.extend_sectors(&rt, params),
    );
    rt.reset();
    check_for_expiration(
        &mut h,
        &rt,
        old_sector.expiration,
        old_sector.sector_number,
        deadline_index,
        partition_index,
    );
}

#[test]
fn update_expiration2_drop_claims_failure_cases() {
    let (mut h, rt) = setup();
    let policy = Policy::default();
    // add in verified deal
    let verified_deals = vec![
        test_activated_deal(h.sector_size as u64 / 2, 1),
        test_activated_deal(h.sector_size as u64 / 2, 2),
    ];
    let old_sector = commit_sector_verified_deals(&verified_deals, &mut h, &rt);
    h.advance_and_submit_posts(&rt, &vec![old_sector.clone()]);

    let state: State = rt.get_state();

    let (deadline_index, partition_index) =
        state.find_sector(rt.store(), old_sector.sector_number).unwrap();

    let extension = 42 * rt.policy().wpost_proving_period;
    let new_expiration = old_sector.expiration + extension;

    let claim_ids = [400, 500];
    let client = Address::new_id(3000).id().unwrap();

    let claim0 = make_claim(
        claim_ids[0],
        &old_sector,
        client,
        h.receiver.id().unwrap(),
        new_expiration,
        &verified_deals[0],
        rt.policy.minimum_verified_allocation_term,
    );
    let mut claim1 = make_claim(
        claim_ids[1],
        &old_sector,
        client,
        h.receiver.id().unwrap(),
        new_expiration,
        &verified_deals[1],
        rt.policy.minimum_verified_allocation_term,
    );

    /* Drop claim before grace period */

    let mut claims = HashMap::new();
    claims.insert(claim_ids[0], Ok(claim0.clone()));
    claims.insert(claim_ids[1], Ok(claim1.clone()));

    let params = ExtendSectorExpiration2Params {
        extensions: vec![ExpirationExtension2 {
            deadline: deadline_index,
            partition: partition_index,
            sectors: BitField::new(),
            new_expiration,
            sectors_with_claims: vec![SectorClaim {
                sector_number: old_sector.sector_number,
                maintain_claims: vec![claim_ids[0]],
                drop_claims: vec![claim_ids[1]],
            }],
        }],
    };
    rt.set_epoch(old_sector.expiration - policy.end_of_life_claim_drop_period - 1);
    expect_abort_contains_message(
        ExitCode::USR_FORBIDDEN,
        "attempt to drop claims with 86401 epochs > end of life claim drop period 86400 remaining",
        h.extend_sectors2(&rt, params.clone(), claims.clone()),
    );
    rt.reset();
    rt.set_epoch(old_sector.expiration - policy.end_of_life_claim_drop_period);

    /* Dropped claim not found */
    let mut claims = HashMap::new();
    claims.insert(claim_ids[0], Ok(claim0.clone()));
    claims.insert(claim_ids[1], Err(actor_error!(not_found, "claim not found")));
    expect_abort_contains_message(
        ExitCode::USR_ILLEGAL_ARGUMENT,
        "failed to get claims for sector",
        h.extend_sectors2(&rt, params.clone(), claims.clone()),
    );
    rt.reset();

    /* Dropped claim provider mismatch */
    claim1.provider = h.receiver.id().unwrap() + 7;
    let mut claims = HashMap::new();
    claims.insert(claim_ids[0], Ok(claim0.clone()));
    claims.insert(claim_ids[1], Ok(claim1.clone()));
    expect_abort_contains_message(
        ExitCode::USR_ILLEGAL_ARGUMENT,
        &format!(
            "expected claim provider to be {} but found {}",
            h.receiver.id().unwrap(),
            h.receiver.id().unwrap() + 7
        ),
        h.extend_sectors2(&rt, params.clone(), claims.clone()),
    );
    rt.reset();
    claim1.provider = h.receiver.id().unwrap(); // reset

    /* Dropped claim sector number mismatch */
    claim1.sector = old_sector.sector_number + 7;
    let mut claims = HashMap::new();
    claims.insert(claim_ids[0], Ok(claim0));
    claims.insert(claim_ids[1], Ok(claim1.clone()));
    expect_abort_contains_message(
        ExitCode::USR_ILLEGAL_ARGUMENT,
        &format!(
            "expected claim sector number to be {} but found {}",
            old_sector.sector_number,
            old_sector.sector_number + 7
        ),
        h.extend_sectors2(&rt, params, claims.clone()),
    );
    rt.reset();
    claim1.sector = old_sector.sector_number;
}

fn commit_sector_verified_deals(
    verified_deals: &[ActivatedDeal],
    h: &mut ActorHarness,
    rt: &MockRuntime,
) -> SectorOnChainInfo {
    h.construct_and_verify(rt);
    assert!(!verified_deals.is_empty());

    let mut pcc = ProveCommitConfig::empty();
    pcc.add_activated_deals(h.next_sector_no, verified_deals.to_owned());

    let mut deal_ids: Vec<DealID> = vec![];
    for i in 0..verified_deals.len() {
        deal_ids.push(i as u64);
    }

    let sector_info = &h.commit_and_prove_sectors_with_cfgs(
        rt,
        1,
        DEFAULT_SECTOR_EXPIRATION as u64,
        vec![deal_ids],
        true,
        pcc,
    )[0];

    sector_info.clone()
}

// assert that state tracks an expiration at the provided epoch in the provided deadline and partition for the provided sector
fn check_for_expiration(
    h: &mut ActorHarness,
    rt: &MockRuntime,
    expiration: ChainEpoch,
    sector_number: SectorNumber,
    deadline_index: u64,
    partition_index: u64,
) {
    let new_sector = h.get_sector(rt, sector_number);
    assert_eq!(expiration, new_sector.expiration);
    let state: State = rt.get_state();
    let quant = state.quant_spec_for_deadline(rt.policy(), deadline_index);

    // assert that new expiration exists
    let (_, mut partition) = h.get_deadline_and_partition(rt, deadline_index, partition_index);
    let expiration_set = partition.pop_expired_sectors(rt.store(), expiration - 1, quant).unwrap();
    assert!(expiration_set.is_empty());

    let expiration_set =
        partition.pop_expired_sectors(rt.store(), quant.quantize_up(expiration), quant).unwrap();
    assert_eq!(expiration_set.len(), 1);
    assert!(expiration_set.on_time_sectors.get(sector_number));

    h.check_state(rt);
}

fn assert_sector_verified_space(
    h: &mut ActorHarness,
    rt: &MockRuntime,
    sector_number: SectorNumber,
    v_deal_space: u64,
) {
    let new_sector = h.get_sector(rt, sector_number);
    assert_eq!(
        DealWeight::from(v_deal_space),
        new_sector.verified_deal_weight / (new_sector.expiration - new_sector.power_base_epoch)
    );
}

fn make_claim(
    claim_id: u64,
    sector: &SectorOnChainInfo,
    client: ActorID,
    provider: ActorID,
    new_expiration: ChainEpoch,
    deal: &ActivatedDeal,
    term_min: ChainEpoch,
) -> FILPlusClaim {
    FILPlusClaim {
        provider,
        client,
        data: make_piece_cid(format!("piece for claim {}", claim_id).as_bytes()),
        size: deal.size,
        term_min,
        term_max: new_expiration - sector.activation,
        term_start: sector.activation,
        sector: sector.sector_number,
    }
}
