// Copyright 2019-2022 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use frc46_token::receiver::{FRC46_TOKEN_TYPE, FRC46TokenReceived};
use frc46_token::token::TOKEN_PRECISION;
use frc46_token::token::types::{BurnParams, TransferParams};
use fvm_actor_utils::receiver::UniversalReceiverParams;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::RawBytes;
use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_shared::address::Address;
use fvm_shared::bigint::BigInt;
use fvm_shared::clock::ChainEpoch;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::sys::SendFlags;
use fvm_shared::{ActorID, METHOD_CONSTRUCTOR};
use log::info;
use num_derive::FromPrimitive;
use num_traits::{Signed, Zero};

use fil_actors_runtime::cbor::deserialize;
use fil_actors_runtime::runtime::builtins::Type;
use fil_actors_runtime::runtime::{ActorCode, Policy, Runtime};
use fil_actors_runtime::{ActorContext, AsActorError, BatchReturnGen};
use fil_actors_runtime::{
    ActorError, BatchReturn, DATACAP_TOKEN_ACTOR_ADDR, STORAGE_MARKET_ACTOR_ADDR,
    SYSTEM_ACTOR_ADDR, VERIFIED_REGISTRY_ACTOR_ADDR, actor_dispatch, actor_error,
    deserialize_block, extract_send_result, resolve_to_actor_id,
};

use crate::ext::datacap::{DestroyParams, MintParams};
use crate::state::{
    DATACAP_MAP_CONFIG, DataCapMap, REMOVE_DATACAP_PROPOSALS_CONFIG, RemoveDataCapProposalMap,
};

pub use self::state::Allocation;
pub use self::state::Claim;
pub use self::state::State;
pub use self::types::*;

#[cfg(feature = "fil-actor")]
fil_actors_runtime::wasm_trampoline!(Actor);

mod emit;

pub mod expiration;
pub mod ext;
pub mod state;
pub mod testing;
pub mod types;

/// Account actor methods available
#[derive(FromPrimitive)]
#[repr(u64)]
pub enum Method {
    Constructor = METHOD_CONSTRUCTOR,
    AddVerifier = 2,
    RemoveVerifier = 3,
    AddVerifiedClient = 4,
    // UseBytes = 5,     // Deprecated
    // RestoreBytes = 6, // Deprecated
    RemoveVerifiedClientDataCap = 7,
    RemoveExpiredAllocations = 8,
    ClaimAllocations = 9,
    GetClaims = 10,
    ExtendClaimTerms = 11,
    RemoveExpiredClaims = 12,
    // Method numbers derived from FRC-0042 standards
    AddVerifiedClientExported = frc42_dispatch::method_hash!("AddVerifiedClient"),
    RemoveExpiredAllocationsExported = frc42_dispatch::method_hash!("RemoveExpiredAllocations"),
    GetClaimsExported = frc42_dispatch::method_hash!("GetClaims"),
    ExtendClaimTermsExported = frc42_dispatch::method_hash!("ExtendClaimTerms"),
    RemoveExpiredClaimsExported = frc42_dispatch::method_hash!("RemoveExpiredClaims"),
    UniversalReceiverHook = frc42_dispatch::method_hash!("Receive"),
}

pub struct Actor;

impl Actor {
    /// Constructor for Registry Actor
    pub fn constructor(rt: &impl Runtime, params: ConstructorParams) -> Result<(), ActorError> {
        rt.validate_immediate_caller_is(std::iter::once(&SYSTEM_ACTOR_ADDR))?;

        // root should be an ID address
        let id_addr = rt
            .resolve_address(&params.root_key)
            .context_code(ExitCode::USR_ILLEGAL_ARGUMENT, "root should be an ID address")?;

        let st = State::new(rt.store(), Address::new_id(id_addr))
            .context("failed to create verifreg state")?;

        rt.create(&st)?;
        Ok(())
    }

    pub fn add_verifier(rt: &impl Runtime, params: AddVerifierParams) -> Result<(), ActorError> {
        if params.allowance < rt.policy().minimum_verified_allocation_size {
            return Err(actor_error!(
                illegal_argument,
                "Allowance {} below minimum deal size for add verifier {}",
                params.allowance,
                params.address
            ));
        }

        let verifier = resolve_to_actor_id(rt, &params.address, true)?;
        let verifier_addr = Address::new_id(verifier);

        let st: State = rt.state()?;
        rt.validate_immediate_caller_is(std::iter::once(&st.root_key))?;

        // Disallow root as a verifier.
        if verifier_addr == st.root_key {
            return Err(actor_error!(illegal_argument, "Rootkey cannot be added as verifier"));
        }

        // Disallow existing clients as verifiers.
        let token_balance = balance(rt, &verifier_addr)?;
        if token_balance.is_positive() {
            return Err(actor_error!(
                illegal_argument,
                "verified client {} cannot become a verifier",
                verifier_addr
            ));
        }

        // Store the new verifier and allowance (over-writing).
        rt.transaction(|st: &mut State, rt| {
            st.put_verifier(rt.store(), &verifier_addr, &params.allowance)
                .context("failed to add verifier")
        })?;

        emit::verifier_balance(rt, verifier, &params.allowance, None)
    }

    pub fn remove_verifier(
        rt: &impl Runtime,
        params: RemoveVerifierParams,
    ) -> Result<(), ActorError> {
        let verifier = resolve_to_actor_id(rt, &params.verifier, false)?;
        let verifier_addr = Address::new_id(verifier);

        rt.transaction(|st: &mut State, rt| {
            rt.validate_immediate_caller_is(std::iter::once(&st.root_key))?;
            st.remove_verifier(rt.store(), &verifier_addr).context("failed to remove verifier")
        })?;

        emit::verifier_balance(rt, verifier, &DataCap::zero(), None)
    }

    pub fn add_verified_client(
        rt: &impl Runtime,
        params: AddVerifiedClientParams,
    ) -> Result<(), ActorError> {
        // The caller will be verified by checking table below
        rt.validate_immediate_caller_accept_any()?;

        if params.allowance < rt.policy().minimum_verified_allocation_size {
            return Err(actor_error!(
                illegal_argument,
                "allowance {} below MinVerifiedDealSize for add verified client {}",
                params.allowance,
                params.address
            ));
        }

        let client_id = resolve_to_actor_id(rt, &params.address, true)?;
        let client = Address::new_id(client_id);

        rt.transaction(|st: &mut State, rt| {
            if client == st.root_key {
                return Err(actor_error!(illegal_argument, "root cannot be added as client"));
            }

            // Validate caller is one of the verifiers, i.e. has an allowance (even if zero).
            let verifier_addr = rt.message().caller();
            let verifier_cap =
                st.get_verifier_cap(rt.store(), &verifier_addr)?.ok_or_else(|| {
                    actor_error!(not_found, "caller {} is not a verifier", verifier_addr)
                })?;

            // Disallow existing verifiers as clients.
            if st.get_verifier_cap(rt.store(), &client)?.is_some() {
                return Err(actor_error!(
                    illegal_argument,
                    "verifier {} cannot be added as a verified client",
                    client
                ));
            }

            // Compute new verifier allowance.
            if verifier_cap < params.allowance {
                return Err(actor_error!(
                    illegal_argument,
                    "add more DataCap {} for client than allocated {}",
                    params.allowance,
                    verifier_cap
                ));
            }

            // Reduce verifier's cap.
            let new_verifier_cap = verifier_cap - &params.allowance;
            st.put_verifier(rt.store(), &verifier_addr, &new_verifier_cap)
                .context("failed to update verifier allowance")?;

            emit::verifier_balance(
                rt,
                verifier_addr.id().unwrap(),
                &new_verifier_cap,
                Some(client.id().unwrap()),
            )
        })?;

        // Credit client token allowance.
        let operators = vec![STORAGE_MARKET_ACTOR_ADDR];
        mint(rt, &client, &params.allowance, operators).context(format!(
            "failed to mint {} data cap to client {}",
            &params.allowance, client
        ))?;
        Ok(())
    }

    /// Removes DataCap allocated to a verified client.
    pub fn remove_verified_client_data_cap(
        rt: &impl Runtime,
        params: RemoveDataCapParams,
    ) -> Result<RemoveDataCapReturn, ActorError> {
        let client = resolve_to_actor_id(rt, &params.verified_client_to_remove, false)?;
        let client = Address::new_id(client);

        let verifier_1 = resolve_to_actor_id(rt, &params.verifier_request_1.verifier, true)?;
        let verifier_1 = Address::new_id(verifier_1);

        let verifier_2 = resolve_to_actor_id(rt, &params.verifier_request_2.verifier, true)?;
        let verifier_2 = Address::new_id(verifier_2);

        if verifier_1 == verifier_2 {
            return Err(actor_error!(
                illegal_argument,
                "need two different verifiers to send remove datacap request"
            ));
        }

        let (verifier_1_id, verifier_2_id) = rt.transaction(|st: &mut State, rt| {
            rt.validate_immediate_caller_is(std::iter::once(&st.root_key))?;

            if params.verified_client_to_remove == VERIFIED_REGISTRY_ACTOR_ADDR {
                return Err(actor_error!(
                    illegal_argument,
                    "cannot remove data cap from verified registry itself"
                ));
            }

            if !is_verifier(rt, st, verifier_1)? {
                return Err(actor_error!(not_found, "{} is not a verifier", verifier_1));
            }

            if !is_verifier(rt, st, verifier_2)? {
                return Err(actor_error!(not_found, "{} is not a verifier", verifier_2));
            }

            // validate signatures
            let mut proposal_ids = RemoveDataCapProposalMap::load(
                rt.store(),
                &st.remove_data_cap_proposal_ids,
                REMOVE_DATACAP_PROPOSALS_CONFIG,
                "remove datacap proposals",
            )?;

            let verifier_1_id = use_proposal_id(&mut proposal_ids, verifier_1, client)?;
            let verifier_2_id = use_proposal_id(&mut proposal_ids, verifier_2, client)?;

            // Assume proposal ids are valid and increment them
            st.remove_data_cap_proposal_ids = proposal_ids.flush()?;
            Ok((verifier_1_id, verifier_2_id))
        })?;

        // Now make sure the proposals were actually valid. We had to increment them first in case
        // re-entrant calls do anything funny.
        //
        // If this fails, we'll revert and the proposals will be restored.
        remove_data_cap_request_is_valid(
            rt,
            &params.verifier_request_1,
            verifier_1_id,
            &params.data_cap_amount_to_remove,
            client,
        )?;
        remove_data_cap_request_is_valid(
            rt,
            &params.verifier_request_2,
            verifier_2_id,
            &params.data_cap_amount_to_remove,
            client,
        )?;

        // Burn the client's data cap tokens.
        let balance = balance(rt, &client).context("failed to fetch balance")?;
        let burnt = std::cmp::min(balance, params.data_cap_amount_to_remove);
        destroy(rt, &client, &burnt)
            .context(format!("failed to destroy {} from allowance for {}", &burnt, &client))?;

        Ok(RemoveDataCapReturn {
            verified_client: client, // Changed to the resolved address
            data_cap_removed: burnt,
        })
    }

    // An allocation may be removed after its expiration epoch has passed (by anyone).
    // When removed, the DataCap tokens are transferred back to the client.
    // If no allocations are specified, all eligible allocations are removed.
    pub fn remove_expired_allocations(
        rt: &impl Runtime,
        params: RemoveExpiredAllocationsParams,
    ) -> Result<RemoveExpiredAllocationsReturn, ActorError> {
        // Since the allocations are expired, this is safe to be called by anyone.
        rt.validate_immediate_caller_accept_any()?;
        let curr_epoch = rt.curr_epoch();
        let mut batch_ret = BatchReturn::empty();
        let mut considered = Vec::<ClaimID>::new();
        let mut recovered_datacap = DataCap::zero();
        let recovered_datacap = rt
            .transaction(|st: &mut State, rt| {
                let mut allocs = st.load_allocs(rt.store())?;

                let to_remove: Vec<&AllocationID>;
                if params.allocation_ids.is_empty() {
                    // Find all expired allocations for the client.
                    considered = expiration::find_expired(&mut allocs, params.client, curr_epoch)?;
                    batch_ret = BatchReturn::ok(considered.len() as u32);
                    to_remove = considered.iter().collect();
                } else {
                    considered = params.allocation_ids.clone();
                    batch_ret = expiration::check_expired(
                        &mut allocs,
                        &params.allocation_ids,
                        params.client,
                        curr_epoch,
                    )?;
                    to_remove = batch_ret.successes(&params.allocation_ids);
                }

                for id in to_remove {
                    let existing = allocs
                        .remove(params.client, *id)
                        .context_code(
                            ExitCode::USR_ILLEGAL_STATE,
                            format!("failed to remove allocation {}", id),
                        )?
                        .unwrap(); // Unwrapping here as both paths to here should ensure the allocation exists.

                    emit::allocation_removed(rt, *id, &existing)?;

                    // Unwrapping here as both paths to here should ensure the allocation exists.
                    recovered_datacap += existing.size.0;
                }

                st.save_allocs(&mut allocs)?;
                Ok(recovered_datacap)
            })
            .context("state transaction failed")?;

        // Transfer the recovered datacap back to the client.
        transfer(rt, params.client, &recovered_datacap).with_context(|| {
            format!(
                "failed to transfer recovered datacap {} back to client {}",
                &recovered_datacap, params.client
            )
        })?;

        Ok(RemoveExpiredAllocationsReturn {
            considered,
            results: batch_ret,
            datacap_recovered: recovered_datacap,
        })
    }

    /// Called by storage provider actor to claim allocations for data provably committed to storage.
    /// For each allocation claim, the registry checks that the provided piece CID
    /// and size match that of the allocation.
    /// Claims are processed in groups by sector. A failed claim will cause the
    /// others in its group to fail too, unless `all_or_nothing` is enabled, in which case
    /// the method will abort.
    /// Returns an indicator of success for each sector group, and the size of claimed space.
    pub fn claim_allocations(
        rt: &impl Runtime,
        params: ClaimAllocationsParams,
    ) -> Result<ClaimAllocationsReturn, ActorError> {
        rt.validate_immediate_caller_type(std::iter::once(&Type::Miner))?;
        let provider = rt.message().caller().id().unwrap();
        if params.sectors.is_empty() {
            return Err(actor_error!(illegal_argument, "claim allocations called with no claims"));
        }

        let mut batch_gen = BatchReturnGen::new(params.sectors.len());
        let mut sector_results: Vec<SectorClaimSummary> = vec![];
        let mut total_claimed_space = DataCap::zero();

        rt.transaction(|st: &mut State, rt| {
            let mut claims = st.load_claims(rt.store())?;
            let mut allocs = st.load_allocs(rt.store())?;

            // Note: this doesn't prevent being called with the same sector number twice.
            'sectors: for sector in params.sectors {
                // Load and validate all allocations for the sector group before
                // making any state changes.
                // Errors cause the sector to be skipped, unless all-or-nothing is requested.
                let mut sector_new_claims: Vec<(ClaimID, Claim)> = vec![];
                for claim in sector.claims {
                    let maybe_alloc =
                        state::get_allocation(&mut allocs, claim.client, claim.allocation_id)?;
                    if let Some(alloc) = maybe_alloc {
                        if !can_claim_alloc(&claim, provider, alloc, rt.curr_epoch(), sector.expiry)
                        {
                            info!(
                                "failed to claim allocation {} in sector {} expiry {}",
                                claim.allocation_id, sector.sector, sector.expiry
                            );
                            batch_gen.add_fail(ExitCode::USR_FORBIDDEN);
                            continue 'sectors;
                        }
                        sector_new_claims.push((
                            claim.allocation_id,
                            Claim {
                                provider,
                                client: alloc.client,
                                data: alloc.data,
                                size: alloc.size,
                                term_min: alloc.term_min,
                                term_max: alloc.term_max,
                                term_start: rt.curr_epoch(),
                                sector: sector.sector,
                            },
                        ));
                    } else {
                        info!("no allocation {} for client {}", claim.allocation_id, claim.client);
                        batch_gen.add_fail(ExitCode::USR_NOT_FOUND);
                        continue 'sectors;
                    }
                }

                // Update state.
                // Errors from here on are unexpected, so abort.
                let mut sector_claimed_space = DataCap::zero();
                for (id, new_claim) in sector_new_claims {
                    let inserted =
                        claims.put_if_absent(provider, id, new_claim.clone()).context_code(
                            ExitCode::USR_ILLEGAL_STATE,
                            format!("failed to write claim {}", id),
                        )?;
                    if !inserted {
                        return Err(actor_error!(illegal_argument, "claim {} already exists", id));
                    }

                    // Emit a claim event below
                    emit::claim(rt, id, &new_claim)?;

                    allocs.remove(new_claim.client, id).context_code(
                        ExitCode::USR_ILLEGAL_STATE,
                        format!("failed to remove allocation {}", id),
                    )?;
                    sector_claimed_space += DataCap::from(new_claim.size.0);
                }
                total_claimed_space += &sector_claimed_space;
                sector_results.push(SectorClaimSummary { claimed_space: sector_claimed_space });
                batch_gen.add_success();
            }
            st.save_allocs(&mut allocs)?;
            st.save_claims(&mut claims)?;
            Ok(())
        })
        .context("state transaction failed")?;

        let batch_info = batch_gen.generate();
        if params.all_or_nothing && !batch_info.all_ok() {
            return Err(ActorError::checked(
                // Returning the first actual error code from the batch might be better, but
                // would change behaviour from the original implementation.
                ExitCode::USR_ILLEGAL_ARGUMENT,
                format!("claim failed with all-or-nothing: {}", batch_info),
                None,
            ));
        }

        // Burn the datacap tokens from verified registry's own balance.
        burn(rt, &total_claimed_space)?;
        Ok(ClaimAllocationsReturn { sector_results: batch_info, sector_claims: sector_results })
    }

    // get claims for a provider
    pub fn get_claims(
        rt: &impl Runtime,
        params: GetClaimsParams,
    ) -> Result<GetClaimsReturn, ActorError> {
        rt.validate_immediate_caller_accept_any()?;
        let mut batch_gen = BatchReturnGen::new(params.claim_ids.len());
        let st: State = rt.state()?;
        let mut st_claims = st.load_claims(rt.store())?;
        let mut claims = Vec::new();
        for id in params.claim_ids {
            let maybe_claim = state::get_claim(&mut st_claims, params.provider, id)?;
            match maybe_claim {
                None => {
                    batch_gen.add_fail(ExitCode::USR_NOT_FOUND);
                    info!("no claim {} for provider {}", id, params.provider,);
                }
                Some(claim) => {
                    batch_gen.add_success();
                    claims.push(claim.clone());
                }
            };
        }

        Ok(GetClaimsReturn { batch_info: batch_gen.generate(), claims })
    }

    /// Extends the maximum term of some claims up to the largest value they could have been
    /// originally allocated.
    /// Callable only by the claims' client.
    /// Cannot reduce a claim's term.
    /// Can extend the term even if the claim has already expired.
    /// Note that this method can't extend the term past the original limit,
    /// even if the term has previously been extended past that by spending new datacap.
    pub fn extend_claim_terms(
        rt: &impl Runtime,
        params: ExtendClaimTermsParams,
    ) -> Result<ExtendClaimTermsReturn, ActorError> {
        // Permissions are checked per-claim.
        rt.validate_immediate_caller_accept_any()?;
        let caller_id = rt.message().caller().id().unwrap();
        let term_limit = rt.policy().maximum_verified_allocation_term;
        let mut batch_gen = BatchReturnGen::new(params.terms.len());
        rt.transaction(|st: &mut State, rt| {
            let mut st_claims = st.load_claims(rt.store())?;
            for term in params.terms {
                // Confirm the new term limit is allowed.
                if term.term_max > term_limit {
                    batch_gen.add_fail(ExitCode::USR_ILLEGAL_ARGUMENT);
                    info!(
                        "term_max {} for claim {} exceeds maximum {}",
                        term.term_max, term.claim_id, term_limit,
                    );
                    continue;
                }

                let maybe_claim = state::get_claim(&mut st_claims, term.provider, term.claim_id)?;
                if let Some(claim) = maybe_claim {
                    // Confirm the caller is the claim's client.
                    if claim.client != caller_id {
                        batch_gen.add_fail(ExitCode::USR_FORBIDDEN);
                        info!(
                            "client {} for claim {} does not match caller {}",
                            claim.client, term.claim_id, caller_id,
                        );
                        continue;
                    }
                    // Confirm the new term limit is no less than the old one.
                    if term.term_max < claim.term_max {
                        batch_gen.add_fail(ExitCode::USR_ILLEGAL_ARGUMENT);
                        info!(
                            "term_max {} for claim {} is less than current {}",
                            term.term_max, term.claim_id, claim.term_max,
                        );
                        continue;
                    }

                    let new_claim = Claim { term_max: term.term_max, ..*claim };
                    st_claims.put(term.provider, term.claim_id, new_claim.clone()).context_code(
                        ExitCode::USR_ILLEGAL_STATE,
                        "HAMT put failure storing new claims",
                    )?;
                    batch_gen.add_success();
                    emit::claim_updated(rt, term.claim_id, &new_claim)?;
                } else {
                    batch_gen.add_fail(ExitCode::USR_NOT_FOUND);
                    info!("no claim {} for provider {}", term.claim_id, term.provider);
                }
            }
            st.save_claims(&mut st_claims)?;
            Ok(())
        })
        .context("state transaction failed")?;
        Ok(batch_gen.generate())
    }

    // A claim may be removed after its maximum term has elapsed (by anyone).
    // If no claims are specified, all eligible claims are removed.
    pub fn remove_expired_claims(
        rt: &impl Runtime,
        params: RemoveExpiredClaimsParams,
    ) -> Result<RemoveExpiredClaimsReturn, ActorError> {
        // Since the claims are expired, this is safe to be called by anyone.
        rt.validate_immediate_caller_accept_any()?;
        let curr_epoch = rt.curr_epoch();
        let mut batch_ret = BatchReturn::empty();
        let mut considered = Vec::<ClaimID>::new();
        rt.transaction(|st: &mut State, rt| {
            let mut claims = st.load_claims(rt.store())?;
            let to_remove: Vec<&ClaimID>;
            if params.claim_ids.is_empty() {
                // Find all expired claims for the provider.
                considered = expiration::find_expired(&mut claims, params.provider, curr_epoch)?;
                batch_ret = BatchReturn::ok(considered.len() as u32);
                to_remove = considered.iter().collect();
            } else {
                considered = params.claim_ids.clone();
                batch_ret = expiration::check_expired(
                    &mut claims,
                    &params.claim_ids,
                    params.provider,
                    curr_epoch,
                )?;
                to_remove = batch_ret.successes(&params.claim_ids);
            }

            for id in to_remove {
                let removed = claims
                    .remove(params.provider, *id)
                    .context_code(
                        ExitCode::USR_ILLEGAL_STATE,
                        format!("failed to remove claim {}", id),
                    )?
                    .unwrap();

                emit::claim_removed(rt, *id, &removed)?;
            }

            st.save_claims(&mut claims)?;
            Ok(())
        })
        .context("state transaction failed")?;

        Ok(RemoveExpiredClaimsReturn { considered, results: batch_ret })
    }

    // Receives data cap tokens (only) and creates allocations according to one or more
    // allocation requests specified in the transfer's operator data.
    // The token amount received must exactly correspond to the sum of the requested allocation sizes.
    // This method does not support partial success (yet): all allocations must succeed,
    // or the transfer will be rejected.
    // Returns the ids of the created allocations.
    pub fn universal_receiver_hook(
        rt: &impl Runtime,
        params: UniversalReceiverParams,
    ) -> Result<AllocationsResponse, ActorError> {
        // Accept only the data cap token.
        rt.validate_immediate_caller_is(&[DATACAP_TOKEN_ACTOR_ADDR])?;

        let my_id = rt.message().receiver().id().unwrap();
        let curr_epoch = rt.curr_epoch();

        // Validate receiver hook payload.
        let tokens_received = validate_tokens_received(&params, my_id)?;
        let client = tokens_received.from;

        // Extract and validate allocation request from the operator data.
        let reqs: AllocationRequests =
            deserialize(&tokens_received.operator_data, "allocation requests")?;
        let mut datacap_total = DataCap::zero();

        // Construct new allocation records.
        let mut new_allocs = Vec::with_capacity(reqs.allocations.len());
        for req in &reqs.allocations {
            validate_new_allocation(req, rt.policy(), curr_epoch)?;
            // Require the provider for new allocations to be a miner actor.
            // This doesn't matter much, but is more ergonomic to fail rather than lock up datacap.
            check_miner_id(rt, req.provider)?;
            new_allocs.push(Allocation {
                client,
                provider: req.provider,
                data: req.data,
                size: req.size,
                term_min: req.term_min,
                term_max: req.term_max,
                expiration: req.expiration,
            });
            datacap_total += DataCap::from(req.size.0);
        }

        let st: State = rt.state()?;
        let mut claims = st.load_claims(rt.store())?;
        let mut updated_claims = Vec::<(ClaimID, Claim)>::new();
        let mut extension_total = DataCap::zero();
        for req in &reqs.extensions {
            // Note: we don't check the client address here, by design.
            // Any client can spend datacap to extend an existing claim.
            let claim = state::get_claim(&mut claims, req.provider, req.claim)?
                .with_context_code(ExitCode::USR_NOT_FOUND, || {
                    format!("no claim {} for provider {}", req.claim, req.provider)
                })?;
            let policy = rt.policy();

            validate_claim_extension(req, claim, policy, curr_epoch)?;
            // The claim's client is not changed to be the address of the token sender.
            // It remains the original allocation client.
            updated_claims.push((req.claim, Claim { term_max: req.term_max, ..*claim }));
            datacap_total += DataCap::from(claim.size.0);
            extension_total += DataCap::from(claim.size.0);
        }

        // Allocation size must match the tokens received exactly (we don't return change).
        let tokens_as_datacap = tokens_to_datacap(&tokens_received.amount);
        if datacap_total != tokens_as_datacap {
            return Err(actor_error!(
                illegal_argument,
                "total allocation size {} must match data cap amount received {}",
                datacap_total,
                tokens_as_datacap
            ));
        }

        // Burn the received datacap tokens spent on extending existing claims.
        // The tokens spent on new allocations will be burnt when claimed later, or refunded.
        burn(rt, &extension_total)?;

        // Partial success isn't supported yet, but these results make space for it in the future.
        let allocation_results = BatchReturn::ok(new_allocs.len() as u32);
        let extension_results = BatchReturn::ok(updated_claims.len() as u32);

        // Save new allocations and updated claims.
        let ids = rt.transaction(|st: &mut State, rt| {
            let ids = st.insert_allocations(rt.store(), client, new_allocs.clone())?;

            for (id, alloc) in ids.iter().zip(new_allocs.iter()) {
                emit::allocation(rt, *id, alloc)?;
            }

            st.put_claims(rt.store(), updated_claims.clone())?;

            for (id, claim) in updated_claims {
                emit::claim_updated(rt, id, &claim)?;
            }

            Ok(ids)
        })?;

        Ok(AllocationsResponse { allocation_results, extension_results, new_allocations: ids })
    }
}

// Checks whether an address has a verifier entry (which could be zero).
fn is_verifier(rt: &impl Runtime, st: &State, address: Address) -> Result<bool, ActorError> {
    let verifiers = DataCapMap::load(rt.store(), &st.verifiers, DATACAP_MAP_CONFIG, "verifiers")?;
    // check that the `address` is currently a verified client
    let found = verifiers.contains_key(&address)?;
    Ok(found)
}

// Invokes Balance on the data cap token actor, and converts the result to whole units of data cap.
fn balance(rt: &impl Runtime, owner: &Address) -> Result<DataCap, ActorError> {
    let params = IpldBlock::serialize_cbor(owner)?;
    let x: TokenAmount = deserialize_block(
        extract_send_result(rt.send(
            &DATACAP_TOKEN_ACTOR_ADDR,
            ext::datacap::Method::Balance as u64,
            params,
            TokenAmount::zero(),
            None,
            SendFlags::READ_ONLY,
        ))
        .context(format!("failed to query datacap balance of {}", owner))?,
    )?;
    Ok(tokens_to_datacap(&x))
}

// Invokes Mint on a data cap token actor for whole units of data cap.
fn mint(
    rt: &impl Runtime,
    to: &Address,
    amount: &DataCap,
    operators: Vec<Address>,
) -> Result<(), ActorError> {
    let token_amt = datacap_to_tokens(amount);
    let params = MintParams { to: *to, amount: token_amt, operators };
    extract_send_result(rt.send_simple(
        &DATACAP_TOKEN_ACTOR_ADDR,
        ext::datacap::Method::Mint as u64,
        IpldBlock::serialize_cbor(&params)?,
        TokenAmount::zero(),
    ))
    .context(format!("failed to send mint {:?} to datacap", params))?;
    Ok(())
}

// Invokes Burn on a data cap token actor for whole units of data cap.
fn burn(rt: &impl Runtime, amount: &DataCap) -> Result<(), ActorError> {
    if amount.is_zero() {
        return Ok(());
    }

    let token_amt = datacap_to_tokens(amount);
    let params = BurnParams { amount: token_amt };
    extract_send_result(rt.send_simple(
        &DATACAP_TOKEN_ACTOR_ADDR,
        ext::datacap::Method::Burn as u64,
        IpldBlock::serialize_cbor(&params)?,
        TokenAmount::zero(),
    ))
    .context(format!("failed to send burn {:?} to datacap", params))?;
    // The burn return value gives the new balance, but it's dropped here.
    // This also allows the check for zero burns inside this method.
    Ok(())
}

// Invokes Destroy on a data cap token actor for whole units of data cap.
fn destroy(rt: &impl Runtime, owner: &Address, amount: &DataCap) -> Result<(), ActorError> {
    if amount.is_zero() {
        return Ok(());
    }
    let token_amt = datacap_to_tokens(amount);
    let params = DestroyParams { owner: *owner, amount: token_amt };
    extract_send_result(rt.send_simple(
        &DATACAP_TOKEN_ACTOR_ADDR,
        ext::datacap::Method::Destroy as u64,
        IpldBlock::serialize_cbor(&params)?,
        TokenAmount::zero(),
    ))
    .context(format!("failed to send destroy {:?} to datacap", params))?;
    Ok(())
}

// Invokes transfer on a data cap token actor for whole units of data cap.
fn transfer(rt: &impl Runtime, to: ActorID, amount: &DataCap) -> Result<(), ActorError> {
    let token_amt = datacap_to_tokens(amount);
    let params = TransferParams {
        to: Address::new_id(to),
        amount: token_amt,
        operator_data: Default::default(),
    };
    extract_send_result(rt.send_simple(
        &DATACAP_TOKEN_ACTOR_ADDR,
        ext::datacap::Method::Transfer as u64,
        IpldBlock::serialize_cbor(&params)?,
        TokenAmount::zero(),
    ))
    .context(format!("failed to send transfer to datacap {:?}", params))?;
    Ok(())
}

fn datacap_to_tokens(amount: &DataCap) -> TokenAmount {
    TokenAmount::from_atto(amount.clone()) * TOKEN_PRECISION
}

fn tokens_to_datacap(amount: &TokenAmount) -> BigInt {
    amount.atto() / TOKEN_PRECISION
}

fn use_proposal_id<BS>(
    proposal_ids: &mut RemoveDataCapProposalMap<BS>,
    verifier: Address,
    client: Address,
) -> Result<RemoveDataCapProposalID, ActorError>
where
    BS: Blockstore,
{
    let key = AddrPairKey::new(verifier, client);
    let maybe_id =
        proposal_ids.get(&key).with_context(|| format!("verifier {verifier} client {client}"))?;

    let curr_id = if let Some(RemoveDataCapProposalID { id }) = maybe_id {
        RemoveDataCapProposalID { id: *id }
    } else {
        RemoveDataCapProposalID { id: 0 }
    };

    let next_id = RemoveDataCapProposalID { id: curr_id.id + 1 };
    proposal_ids
        .set(&key, next_id)
        .with_context(|| format!("verifier {verifier} client {client}"))?;
    Ok(curr_id)
}

fn remove_data_cap_request_is_valid(
    rt: &impl Runtime,
    request: &RemoveDataCapRequest,
    id: RemoveDataCapProposalID,
    to_remove: &DataCap,
    client: Address,
) -> Result<(), ActorError> {
    let proposal = RemoveDataCapProposal {
        removal_proposal_id: id,
        data_cap_amount: to_remove.clone(),
        verified_client: client,
    };

    let b = RawBytes::serialize(proposal).map_err(|e| {
        actor_error!(
                serialization; "failed to marshal remove datacap request: {}", e)
    })?;

    let payload = [SIGNATURE_DOMAIN_SEPARATION_REMOVE_DATA_CAP, b.bytes()].concat();

    if !extract_send_result(rt.send(
        &request.verifier,
        ext::account::AUTHENTICATE_MESSAGE_METHOD,
        IpldBlock::serialize_cbor(&ext::account::AuthenticateMessageParams {
            signature: request.signature.bytes.clone(),
            message: payload,
        })?,
        TokenAmount::zero(),
        None,
        SendFlags::READ_ONLY,
    ))
    .and_then(deserialize_block)
    .context("proposal authentication failed")?
    {
        Err(actor_error!(illegal_argument, "proposal authentication failed"))
    } else {
        Ok(())
    }
}

// Deserializes and validates a receiver hook payload, expecting only an FRC-46 transfer.
fn validate_tokens_received(
    params: &UniversalReceiverParams,
    my_id: u64,
) -> Result<FRC46TokenReceived, ActorError> {
    if params.type_ != FRC46_TOKEN_TYPE {
        return Err(actor_error!(
            illegal_argument,
            "invalid token type {}, expected {} (FRC-46)",
            params.type_,
            FRC46_TOKEN_TYPE
        ));
    }
    let payload: FRC46TokenReceived = deserialize(&params.payload, "receiver hook payload")?;
    // Payload to address must match receiving actor.
    if payload.to != my_id {
        return Err(actor_error!(
            illegal_argument,
            "token receiver expected to {}, was {}",
            my_id,
            payload.to
        ));
    }
    Ok(payload)
}

// Validates an allocation request.
fn validate_new_allocation(
    req: &AllocationRequest,
    policy: &Policy,
    curr_epoch: ChainEpoch,
) -> Result<(), ActorError> {
    // Size must be at least the policy minimum.
    if DataCap::from(req.size.0) < policy.minimum_verified_allocation_size {
        return Err(actor_error!(
            illegal_argument,
            "allocation size {} below minimum {}",
            req.size.0,
            policy.minimum_verified_allocation_size
        ));
    }
    // Term must be at least the policy minimum.
    if req.term_min < policy.minimum_verified_allocation_term {
        return Err(actor_error!(
            illegal_argument,
            "allocation term min {} below limit {}",
            req.term_min,
            policy.minimum_verified_allocation_term
        ));
    }
    // Term cannot exceed the policy maximum.
    if req.term_max > policy.maximum_verified_allocation_term {
        return Err(actor_error!(
            illegal_argument,
            "allocation term max {} above limit {}",
            req.term_max,
            policy.maximum_verified_allocation_term
        ));
    }
    // Term range must be non-empty.
    if req.term_min > req.term_max {
        return Err(actor_error!(
            illegal_argument,
            "allocation term min {} exceeds term max {}",
            req.term_min,
            req.term_max
        ));
    }

    // Allocation must expire in the future.
    if req.expiration < curr_epoch {
        return Err(actor_error!(
            illegal_argument,
            "allocation expiration epoch {} has passed current epoch {}",
            req.expiration,
            curr_epoch
        ));
    }
    // Allocation must expire soon enough.
    let max_expiration = curr_epoch + policy.maximum_verified_allocation_expiration;
    if req.expiration > max_expiration {
        return Err(actor_error!(
            illegal_argument,
            "allocation expiration {} exceeds maximum {}",
            req.expiration,
            max_expiration
        ));
    }
    Ok(())
}

fn validate_claim_extension(
    req: &ClaimExtensionRequest,
    claim: &Claim,
    policy: &Policy,
    curr_epoch: ChainEpoch,
) -> Result<(), ActorError> {
    // The new term max is the policy limit after current epoch (not after the old term max).
    let term_limit_absolute = curr_epoch + policy.maximum_verified_allocation_term;
    let term_limit_relative = term_limit_absolute - claim.term_start;
    if req.term_max > term_limit_relative {
        return Err(actor_error!(
            illegal_argument,
            format!(
                "term_max {} for claim {} exceeds maximum {} at current epoch {}",
                req.term_max, req.claim, term_limit_relative, curr_epoch
            )
        ));
    }
    // The new term max must be larger than the old one.
    // Cannot reduce term, and cannot spend datacap on a zero increase.
    // There is no policy on minimum extension duration.
    if req.term_max <= claim.term_max {
        return Err(actor_error!(
            illegal_argument,
            "term_max {} for claim {} is not larger than existing term max {}",
            req.term_max,
            req.claim,
            claim.term_max
        ));
    }
    // The claim must not have already expired.
    // Unlike when the claim client extends term up to the originally-allowed max,
    // allowing extension of expired claims with new datacap could revive a claim arbitrarily
    // far into the future.
    // A claim can be extended continuously into the future, but once it has expired
    // it is expired for good.
    let claim_expiration = claim.term_start + claim.term_max;
    if curr_epoch > claim_expiration {
        return Err(actor_error!(
            forbidden,
            "claim {} expired at {}, current epoch {}",
            req.claim,
            claim_expiration,
            curr_epoch
        ));
    }
    Ok(())
}

// Checks that an address corresponsds to a miner actor.
fn check_miner_id(rt: &impl Runtime, id: ActorID) -> Result<(), ActorError> {
    let code_cid =
        rt.get_actor_code_cid(&id).with_context_code(ExitCode::USR_ILLEGAL_ARGUMENT, || {
            format!("no code CID for provider {}", id)
        })?;

    let provider_type = rt
        .resolve_builtin_actor_type(&code_cid)
        .with_context_code(ExitCode::USR_ILLEGAL_ARGUMENT, || {
            format!("provider code {} must be built-in miner actor", code_cid)
        })?;
    if provider_type != Type::Miner {
        return Err(actor_error!(
            illegal_argument,
            "allocation provider {} must be a miner actor, was {:?}",
            id,
            provider_type
        ));
    }
    Ok(())
}

fn can_claim_alloc(
    claim_alloc: &AllocationClaim,
    provider: ActorID,
    alloc: &Allocation,
    curr_epoch: ChainEpoch,
    sector_expiry: ChainEpoch,
) -> bool {
    let sector_lifetime = sector_expiry - curr_epoch;
    provider == alloc.provider
        && claim_alloc.client == alloc.client
        && claim_alloc.data == alloc.data
        && claim_alloc.size == alloc.size
        && curr_epoch <= alloc.expiration
        && sector_lifetime >= alloc.term_min
        && sector_lifetime <= alloc.term_max
}

impl ActorCode for Actor {
    type Methods = Method;

    fn name() -> &'static str {
        "VerifiedRegistry"
    }

    actor_dispatch! {
        Constructor => constructor,
        AddVerifier => add_verifier,
        RemoveVerifier => remove_verifier,
        AddVerifiedClient|AddVerifiedClientExported => add_verified_client,
        RemoveVerifiedClientDataCap => remove_verified_client_data_cap,
        RemoveExpiredAllocations|RemoveExpiredAllocationsExported => remove_expired_allocations,
        ClaimAllocations => claim_allocations,
        GetClaims|GetClaimsExported => get_claims,
        ExtendClaimTerms|ExtendClaimTermsExported => extend_claim_terms,
        RemoveExpiredClaims|RemoveExpiredClaimsExported => remove_expired_claims,
        UniversalReceiverHook => universal_receiver_hook,
    }
}
