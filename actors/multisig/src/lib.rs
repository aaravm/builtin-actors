// Copyright 2019-2022 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use std::collections::BTreeSet;

use fvm_actor_utils::receiver::UniversalReceiverParams;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::RawBytes;
use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_shared::METHOD_CONSTRUCTOR;
use fvm_shared::MethodNum;
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use num_derive::FromPrimitive;
use num_traits::Zero;

use fil_actors_runtime::FIRST_EXPORTED_METHOD_NUMBER;
use fil_actors_runtime::cbor::serialize_vec;
use fil_actors_runtime::runtime::{ActorCode, Primitives, Runtime};
use fil_actors_runtime::{
    ActorContext, ActorError, AsActorError, INIT_ACTOR_ADDR, actor_dispatch, actor_error,
    extract_send_result, resolve_to_actor_id,
};

pub use self::state::*;
pub use self::types::*;

#[cfg(feature = "fil-actor")]
fil_actors_runtime::wasm_trampoline!(Actor);

mod state;
pub mod testing;
mod types;

/// Multisig actor methods available
#[derive(FromPrimitive)]
#[repr(u64)]
pub enum Method {
    Constructor = METHOD_CONSTRUCTOR,
    Propose = 2,
    Approve = 3,
    Cancel = 4,
    AddSigner = 5,
    RemoveSigner = 6,
    SwapSigner = 7,
    ChangeNumApprovalsThreshold = 8,
    LockBalance = 9,
    // Method numbers derived from FRC-0042 standards
    UniversalReceiverHook = frc42_dispatch::method_hash!("Receive"),
}

/// Multisig Actor
pub struct Actor;

impl Actor {
    /// Constructor for Multisig actor
    pub fn constructor(rt: &impl Runtime, params: ConstructorParams) -> Result<(), ActorError> {
        rt.validate_immediate_caller_is(std::iter::once(&INIT_ACTOR_ADDR))?;

        if params.signers.is_empty() {
            return Err(actor_error!(illegal_argument; "Must have at least one signer"));
        }

        if params.signers.len() > SIGNERS_MAX {
            return Err(actor_error!(
                illegal_argument,
                "cannot add more than {} signers",
                SIGNERS_MAX
            ));
        }

        // resolve signer addresses and do not allow duplicate signers
        let mut resolved_signers = Vec::with_capacity(params.signers.len());
        let mut dedup_signers = BTreeSet::new();
        for signer in &params.signers {
            let resolved = resolve_to_actor_id(rt, signer, true)?;
            if !dedup_signers.insert(resolved) {
                return Err(
                    actor_error!(illegal_argument; "duplicate signer not allowed: {}", signer),
                );
            }
            resolved_signers.push(Address::new_id(resolved));
        }

        if params.num_approvals_threshold > params.signers.len() as u64 {
            return Err(
                actor_error!(illegal_argument; "must not require more approvals than signers"),
            );
        }

        if params.num_approvals_threshold < 1 {
            return Err(actor_error!(illegal_argument; "must require at least one approval"));
        }

        if params.unlock_duration < 0 {
            return Err(actor_error!(illegal_argument; "negative unlock duration disallowed"));
        }

        let empty_root = PendingTxnMap::empty(rt.store(), PENDING_TXN_CONFIG, "empty").flush()?;

        let mut st: State = State {
            signers: resolved_signers,
            num_approvals_threshold: params.num_approvals_threshold,
            pending_txs: empty_root,
            initial_balance: TokenAmount::zero(),
            next_tx_id: Default::default(),
            start_epoch: Default::default(),
            unlock_duration: Default::default(),
        };

        if params.unlock_duration != 0 {
            st.set_locked(
                params.start_epoch,
                params.unlock_duration,
                rt.message().value_received(),
            );
        }
        rt.create(&st)?;

        Ok(())
    }

    /// Multisig actor propose function
    pub fn propose(rt: &impl Runtime, params: ProposeParams) -> Result<ProposeReturn, ActorError> {
        rt.validate_immediate_caller_accept_any()?;
        let proposer: Address = rt.message().caller();

        if params.value.is_negative() {
            return Err(actor_error!(
                illegal_argument,
                "proposed value must be non-negative, was {}",
                params.value
            ));
        }

        let (txn_id, txn) = rt.transaction(|st: &mut State, rt| {
            if !st.is_signer(&proposer) {
                return Err(actor_error!(forbidden, "{} is not a signer", proposer));
            }

            let mut ptx = PendingTxnMap::load(
                rt.store(),
                &st.pending_txs,
                PENDING_TXN_CONFIG,
                "pending txns",
            )?;
            let t_id = st.next_tx_id;
            st.next_tx_id.0 += 1;

            let txn = Transaction {
                to: params.to,
                value: params.value,
                method: params.method,
                params: params.params,
                approved: Vec::new(),
            };

            ptx.set(&t_id, txn.clone())?;
            st.pending_txs = ptx.flush()?;
            Ok((t_id, txn))
        })?;

        let (applied, ret, code) = Self::approve_transaction(rt, txn_id, txn)?;
        Ok(ProposeReturn { txn_id, applied, code, ret })
    }

    /// Multisig actor approve function
    pub fn approve(rt: &impl Runtime, params: TxnIDParams) -> Result<ApproveReturn, ActorError> {
        rt.validate_immediate_caller_accept_any()?;
        let approver: Address = rt.message().caller();

        let id = params.id;
        let (st, txn) = rt.transaction(|st: &mut State, rt| {
            if !st.is_signer(&approver) {
                return Err(actor_error!(forbidden; "{} is not a signer", approver));
            }
            let ptx = PendingTxnMap::load(
                rt.store(),
                &st.pending_txs,
                PENDING_TXN_CONFIG,
                "pending txns",
            )?;

            let txn = get_transaction(rt, &ptx, params.id, params.proposal_hash)?;

            // Go implementation holds reference to state after transaction so state must be cloned
            // to match to handle possible exit code inconsistency
            Ok((st.clone(), txn.clone()))
        })?;

        let (applied, ret, code) = execute_transaction_if_approved(rt, &st, id, &txn)?;
        if !applied {
            // if the transaction hasn't already been approved, "process" the approval
            // and see if the transaction can be executed
            let (applied, ret, code) = Self::approve_transaction(rt, id, txn)?;
            Ok(ApproveReturn { applied, code, ret })
        } else {
            Ok(ApproveReturn { applied, code, ret })
        }
    }

    /// Multisig actor cancel function
    pub fn cancel(rt: &impl Runtime, params: TxnIDParams) -> Result<(), ActorError> {
        rt.validate_immediate_caller_accept_any()?;
        let caller_addr: Address = rt.message().caller();

        rt.transaction(|st: &mut State, rt| {
            if !st.is_signer(&caller_addr) {
                return Err(actor_error!(forbidden; "{} is not a signer", caller_addr));
            }

            let mut ptx = PendingTxnMap::load(
                rt.store(),
                &st.pending_txs,
                PENDING_TXN_CONFIG,
                "pending txns",
            )?;

            let tx = ptx.delete(&params.id)?.ok_or_else(|| {
                actor_error!(not_found, "no such transaction {:?} to cancel", params.id)
            })?;

            // Check to make sure transaction proposer is caller address
            if tx.approved.first() != Some(&caller_addr) {
                return Err(actor_error!(forbidden; "Cannot cancel another signers transaction"));
            }

            let calculated_hash = compute_proposal_hash(&tx, rt)
                .with_context_code(ExitCode::USR_ILLEGAL_STATE, || {
                    format!("failed to compute proposal hash for (tx: {:?})", params.id)
                })?;

            if !params.proposal_hash.is_empty() && params.proposal_hash != calculated_hash {
                return Err(actor_error!(illegal_state, "hash does not match proposal params"));
            }

            st.pending_txs = ptx.flush()?;
            Ok(())
        })
    }

    /// Multisig actor function to add signers to multisig
    pub fn add_signer(rt: &impl Runtime, params: AddSignerParams) -> Result<(), ActorError> {
        let receiver = rt.message().receiver();
        rt.validate_immediate_caller_is(std::iter::once(&receiver))?;
        let resolved_new_signer = resolve_to_actor_id(rt, &params.signer, true)?;

        rt.transaction(|st: &mut State, _| {
            if st.signers.len() >= SIGNERS_MAX {
                return Err(actor_error!(
                    forbidden,
                    "cannot add more than {} signers",
                    SIGNERS_MAX
                ));
            }
            if st.is_signer(&Address::new_id(resolved_new_signer)) {
                return Err(actor_error!(forbidden, "{} is already a signer", resolved_new_signer));
            }

            // Add signer and increase threshold if set
            st.signers.push(Address::new_id(resolved_new_signer));
            if params.increase {
                st.num_approvals_threshold += 1;
            }

            Ok(())
        })
    }

    /// Multisig actor function to remove signers to multisig
    pub fn remove_signer(rt: &impl Runtime, params: RemoveSignerParams) -> Result<(), ActorError> {
        let receiver = rt.message().receiver();
        rt.validate_immediate_caller_is(std::iter::once(&receiver))?;
        let resolved_old_signer = resolve_to_actor_id(rt, &params.signer, false)?;

        rt.transaction(|st: &mut State, rt| {
            if !st.is_signer(&Address::new_id(resolved_old_signer)) {
                return Err(actor_error!(forbidden, "{} is not a signer", resolved_old_signer));
            }

            if st.signers.len() == 1 {
                return Err(actor_error!(forbidden; "Cannot remove only signer"));
            }

            if !params.decrease && ((st.signers.len() - 1) as u64) < st.num_approvals_threshold {
                return Err(actor_error!(
                    illegal_argument,
                    "can't reduce signers to {} below threshold {} with decrease=false",
                    st.signers.len(),
                    st.num_approvals_threshold
                ));
            }

            if params.decrease {
                if st.num_approvals_threshold < 2 {
                    return Err(actor_error!(
                        illegal_argument,
                        "can't decrease approvals from {} to {}",
                        st.num_approvals_threshold,
                        st.num_approvals_threshold - 1
                    ));
                }
                st.num_approvals_threshold -= 1;
            }

            // Remove approvals from removed signer
            st.purge_approvals(rt.store(), &Address::new_id(resolved_old_signer))
                .context("failed to purge approvals of removed signer")?;
            st.signers.retain(|s| s != &Address::new_id(resolved_old_signer));

            Ok(())
        })?;

        Ok(())
    }

    /// Multisig actor function to swap signers to multisig
    pub fn swap_signer(rt: &impl Runtime, params: SwapSignerParams) -> Result<(), ActorError> {
        let receiver = rt.message().receiver();
        rt.validate_immediate_caller_is(std::iter::once(&receiver))?;
        let from_resolved = resolve_to_actor_id(rt, &params.from, false)?;
        let to_resolved = resolve_to_actor_id(rt, &params.to, true)?;

        rt.transaction(|st: &mut State, rt| {
            if !st.is_signer(&Address::new_id(from_resolved)) {
                return Err(actor_error!(forbidden; "{} is not a signer", from_resolved));
            }

            if st.is_signer(&Address::new_id(to_resolved)) {
                return Err(actor_error!(illegal_argument; "{} is already a signer", to_resolved));
            }

            // Remove signer from state (retain preserves order of elements)
            st.signers.retain(|s| s != &Address::new_id(from_resolved));

            // Add new signer
            st.signers.push(Address::new_id(to_resolved));

            st.purge_approvals(rt.store(), &Address::new_id(from_resolved))?;
            Ok(())
        })?;

        Ok(())
    }

    /// Multisig actor function to change number of approvals needed
    pub fn change_num_approvals_threshold(
        rt: &impl Runtime,
        params: ChangeNumApprovalsThresholdParams,
    ) -> Result<(), ActorError> {
        let receiver = rt.message().receiver();
        rt.validate_immediate_caller_is(std::iter::once(&receiver))?;

        rt.transaction(|st: &mut State, _| {
            // Check if valid threshold value
            if params.new_threshold == 0 || params.new_threshold > st.signers.len() as u64 {
                return Err(actor_error!(illegal_argument; "New threshold value not supported"));
            }

            // Update threshold on state
            st.num_approvals_threshold = params.new_threshold;
            Ok(())
        })?;

        Ok(())
    }

    /// Multisig actor function to change number of approvals needed
    pub fn lock_balance(rt: &impl Runtime, params: LockBalanceParams) -> Result<(), ActorError> {
        let receiver = rt.message().receiver();
        rt.validate_immediate_caller_is(std::iter::once(&receiver))?;

        if params.unlock_duration <= 0 {
            return Err(actor_error!(illegal_argument, "unlock duration must be positive"));
        }

        if params.amount.is_negative() {
            return Err(actor_error!(illegal_argument, "amount to lock must be positive"));
        }

        rt.transaction(|st: &mut State, _| {
            if st.unlock_duration != 0 {
                return Err(actor_error!(forbidden, "modification of unlock disallowed"));
            }
            st.set_locked(params.start_epoch, params.unlock_duration, params.amount);
            Ok(())
        })?;

        Ok(())
    }

    fn approve_transaction(
        rt: &impl Runtime,
        tx_id: TxnID,
        mut txn: Transaction,
    ) -> Result<(bool, RawBytes, ExitCode), ActorError> {
        for previous_approver in &txn.approved {
            if *previous_approver == rt.message().caller() {
                return Err(actor_error!(
                    forbidden,
                    "{} already approved this message",
                    previous_approver
                ));
            }
        }

        let st = rt.transaction(|st: &mut State, rt| {
            let mut ptx = PendingTxnMap::load(
                rt.store(),
                &st.pending_txs,
                PENDING_TXN_CONFIG,
                "pending txns",
            )?;

            // update approved on the transaction
            txn.approved.push(rt.message().caller());

            ptx.set(&tx_id, txn.clone())?;
            st.pending_txs = ptx.flush()?;

            // Go implementation holds reference to state after transaction so this must be cloned
            // to match to handle possible exit code inconsistency
            Ok(st.clone())
        })?;

        execute_transaction_if_approved(rt, &st, tx_id, &txn)
    }

    // Always succeeds, accepting any transfers, so long as the params are valid `UniversalReceiverParams`.
    pub fn universal_receiver_hook(
        rt: &impl Runtime,
        _params: UniversalReceiverParams,
    ) -> Result<(), ActorError> {
        rt.validate_immediate_caller_accept_any()?;
        Ok(())
    }

    pub fn fallback(
        rt: &impl Runtime,
        method: MethodNum,
        _: Option<IpldBlock>,
    ) -> Result<Option<IpldBlock>, ActorError> {
        rt.validate_immediate_caller_accept_any()?;
        if method >= FIRST_EXPORTED_METHOD_NUMBER {
            Ok(None)
        } else {
            Err(actor_error!(unhandled_message; "invalid method: {}", method))
        }
    }
}

fn execute_transaction_if_approved(
    rt: &impl Runtime,
    st: &State,
    txn_id: TxnID,
    txn: &Transaction,
) -> Result<(bool, RawBytes, ExitCode), ActorError> {
    let mut out = RawBytes::default();
    let mut code = ExitCode::OK;
    let mut applied = false;
    let threshold_met = txn.approved.len() as u64 >= st.num_approvals_threshold;
    if threshold_met {
        st.check_available(rt.current_balance(), &txn.value, rt.curr_epoch())?;

        match extract_send_result(rt.send_simple(
            &txn.to,
            txn.method,
            txn.params.clone().into(),
            txn.value.clone(),
        )) {
            Ok(Some(r)) => {
                out = RawBytes::new(r.data);
            }
            Err(mut e) => {
                if let Some(r) = e.take_data() {
                    out = RawBytes::new(r.data);
                }

                code = e.exit_code();
            }
            _ => {}
        }
        applied = true;

        rt.transaction(|st: &mut State, rt| {
            let mut ptx = PendingTxnMap::load(
                rt.store(),
                &st.pending_txs,
                PENDING_TXN_CONFIG,
                "pending txns",
            )?;
            ptx.delete(&txn_id)?;
            st.pending_txs = ptx.flush()?;
            Ok(())
        })?;
    }

    Ok((applied, out, code))
}

fn get_transaction<'m, BS, RT>(
    rt: &RT,
    ptx: &'m PendingTxnMap<BS>,
    txn_id: TxnID,
    proposal_hash: Vec<u8>,
) -> Result<&'m Transaction, ActorError>
where
    BS: Blockstore,
    RT: Runtime,
{
    let txn = ptx
        .get(&txn_id)?
        .ok_or_else(|| actor_error!(not_found, "no such transaction {:?} for approval", txn_id))?;

    if !proposal_hash.is_empty() {
        let calculated_hash = compute_proposal_hash(txn, rt)
            .with_context_code(ExitCode::USR_ILLEGAL_STATE, || {
                format!("failed to compute proposal hash for (tx: {:?})", txn_id)
            })?;

        if proposal_hash != calculated_hash {
            return Err(actor_error!(
                illegal_argument,
                "hash does not match proposal params (ensure requester is an ID address)"
            ));
        }
    }

    Ok(txn)
}

/// Computes a digest of a proposed transaction. This digest is used to confirm identity
/// of the transaction associated with an ID, which might change under chain re-orgs.
pub fn compute_proposal_hash(txn: &Transaction, sys: &dyn Primitives) -> anyhow::Result<[u8; 32]> {
    let proposal_hash = ProposalHashData {
        requester: txn.approved.first(),
        to: &txn.to,
        value: &txn.value,
        method: &txn.method,
        params: &txn.params,
    };
    let data = serialize_vec(&proposal_hash, "proposal hash")?;
    Ok(sys.hash_blake2b(&data))
}

impl ActorCode for Actor {
    type Methods = Method;

    fn name() -> &'static str {
        "Multisig"
    }

    actor_dispatch! {
      Constructor => constructor,
      Propose => propose,
      Approve => approve,
      Cancel => cancel,
      AddSigner => add_signer,
      RemoveSigner => remove_signer,
      SwapSigner => swap_signer,
      ChangeNumApprovalsThreshold => change_num_approvals_threshold,
      LockBalance => lock_balance,
      UniversalReceiverHook => universal_receiver_hook,
      _ => fallback,
    }
}
