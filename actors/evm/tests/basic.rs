mod asm;

use cid::Cid;
use fil_actor_evm as evm;
use fil_actors_evm_shared::uints::U256;
use fil_actors_runtime::test_utils::*;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_shared::address::Address;

mod util;

#[test]
fn basic_contract_construction_and_invocation_fe_lang() {
    let bytecode =
        hex::decode(include_str!("contracts/output/FeSimplecoin/FeSimplecoin.bin")).unwrap();
    simplecoin_test(bytecode);
}

#[test]
fn basic_contract_construction_and_invocation() {
    let bytecode = hex::decode(include_str!("contracts/simplecoin.hex")).unwrap();
    simplecoin_test(bytecode);
}

fn simplecoin_test(bytecode: Vec<u8>) {
    let contract = Address::new_id(100);

    let rt = util::init_construct_and_verify(bytecode, |rt| {
        rt.actor_code_cids.borrow_mut().insert(contract, *EVM_ACTOR_CODE_ID);
        rt.set_origin(contract);
    });

    // invoke contract -- getBalance
    // first we invoke without specifying an address, so it would be the system actor and have
    // a balance of 0

    let mut solidity_params = vec![];
    solidity_params.append(&mut hex::decode("f8b2cb4f").unwrap()); // function selector
    // caller id address in U256 form
    let mut arg0 = vec![0u8; 32];
    solidity_params.append(&mut arg0);

    let result = util::invoke_contract(&rt, &solidity_params);
    assert_eq!(U256::from_big_endian(&result), U256::from(0));

    // invoke contract -- getBalance
    // now we invoke with the owner address, which should have a balance of 10k
    let mut solidity_params = vec![];
    solidity_params.append(&mut hex::decode("f8b2cb4f").unwrap()); // function selector
    // caller id address in U256 form
    let mut arg0 = vec![0u8; 32];
    arg0[12] = 0xff; // it's an ID address, so we enable the flag
    arg0[31] = 100; // the owner address
    solidity_params.append(&mut arg0);

    let result = util::invoke_contract(&rt, &solidity_params);
    assert_eq!(U256::from_big_endian(&result), U256::from(10000));
}

#[test]
fn basic_get_bytecode() {
    let (init_code, verbatim_body) = {
        let init = "";
        let body = r#"
# get call payload size
push1 0x20
calldatasize
sub
# store payload to mem 0x00
push1 0x20
push1 0x00
calldatacopy
return
"#;

        let body_bytecode = {
            let mut ret = Vec::new();
            let mut ingest = etk_asm::ingest::Ingest::new(&mut ret);
            ingest.ingest("body", body).unwrap();
            ret
        };

        (asm::new_contract("get_bytecode", init, body).unwrap(), body_bytecode)
    };

    let rt = util::construct_and_verify(init_code);

    rt.reset();
    rt.expect_validate_caller_any();
    let returned_bytecode_cid: Cid = rt
        .call::<evm::EvmContractActor>(evm::Method::GetBytecode as u64, None)
        .unwrap()
        .unwrap()
        .deserialize()
        .unwrap();
    rt.verify();

    let bytecode = rt.store.get(&returned_bytecode_cid).unwrap().unwrap();

    assert_eq!(bytecode.as_slice(), verbatim_body.as_slice());
}

#[test]
fn basic_get_storage_at() {
    let init_code = {
        // Initialize storage entry on key 0x8965 during init.
        let init = r"
push2 0xfffa
push2 0x8965
sstore";
        let body = r#"return"#;

        asm::new_contract("get_storage_at", init, body).unwrap()
    };

    let rt = util::construct_and_verify(init_code);

    rt.reset();
    let params = evm::GetStorageAtParams { storage_key: 0x8965.into() };

    let sender = Address::new_id(0); // zero address because this method is not invokable on-chain
    rt.expect_validate_caller_addr(vec![sender]);
    rt.caller.replace(sender);

    //
    // Get the storage key that was initialized in the init code.
    //
    let value: U256 = rt
        .call::<evm::EvmContractActor>(
            evm::Method::GetStorageAt as u64,
            IpldBlock::serialize_cbor(&params).unwrap(),
        )
        .unwrap()
        .unwrap()
        .deserialize()
        .unwrap();
    rt.verify();
    rt.reset();

    assert_eq!(U256::from(0xfffa), value);

    //
    // Get a storage key that doesn't exist, should default to zero.
    //
    let params = evm::GetStorageAtParams { storage_key: 0xaaaa.into() };

    rt.expect_validate_caller_addr(vec![sender]);
    let value: U256 = rt
        .call::<evm::EvmContractActor>(
            evm::Method::GetStorageAt as u64,
            IpldBlock::serialize_cbor(&params).unwrap(),
        )
        .unwrap()
        .unwrap()
        .deserialize()
        .unwrap();

    assert_eq!(U256::from(0), value);
    rt.verify();
}

#[test]
fn test_push_last_byte() {
    // 60 01 # len
    // 80    # dup len
    // 60 0b # offset 0x0b
    // 60 0  # mem offset 0
    // 39    # codecopy (dstOff, off, len)
    //       # stack = [0x01]
    // 60 0  # mem offset 0
    // f3    # return (offset, size)
    // 7f    # (bytecode)

    // // Inputs[1] { @000A  memory[0x00:0x01] }
    // 0000    60  PUSH1 0x01
    // 0002    80  DUP1
    // 0003    60  PUSH1 0x0b
    // 0005    60  PUSH1 0x00
    // 0007    39  CODECOPY
    // 0008    60  PUSH1 0x00
    // 000A    F3  *RETURN
    // // Stack delta = +0
    // // Outputs[2]
    // // {
    // //     @0007  memory[0x00:0x01] = code[0x0b:0x0c]
    // //     @000A  return memory[0x00:0x01];
    // // }
    // // Block terminates

    // 000B    7F    PUSH32 0x

    // function main() {
    //     memory[0x00:0x01] = code[0x0b:0x0c];
    //     return memory[0x00:0x01];
    // }

    // bytecode where push32 opcode is the last/only byte
    let init_code = hex::decode("600180600b6000396000f37f").unwrap();

    let rt = util::construct_and_verify(init_code);

    util::invoke_contract(&rt, &[]);
}

#[test]
fn transient_storage() {
    let transient_storage_bytecode =
        hex::decode(include_str!("contracts/TransientStorageTest.hex")).unwrap();
    transient_storage_test(transient_storage_bytecode);
}

fn transient_storage_test(transient_storage_bytecode: Vec<u8>) {
    let contract = Address::new_id(100);
    let rt = util::init_construct_and_verify(transient_storage_bytecode, |rt| {
        rt.actor_code_cids.borrow_mut().insert(contract, *EVM_ACTOR_CODE_ID);
        rt.set_origin(contract);
    });

    let mut solidity_params = vec![];
    solidity_params.extend_from_slice(&hex::decode("23d74628").unwrap()); // function selector, "runTests()"
    let _result = util::invoke_contract(&rt, &solidity_params);

    // Setup for testing that the transient storage data clears when a new transaction occurs
    let mut solidity_params_test_cleared = vec![];
    solidity_params_test_cleared.extend_from_slice(&hex::decode("54e84d1b").unwrap()); // function selector, "testLifecycleValidationSubsequentTransaction()"
    //
    // We expect this to fail because no changes are made
    util::invoke_contract_expect_fail(&rt, &solidity_params_test_cleared);

    // use a new address for our calling context; this will cause the transient storage
    // data to reset because the transient storage lifecycle value has changed
    let new_context = Address::new_id(200);
    rt.set_origin(new_context);

    util::invoke_contract(&rt, &solidity_params_test_cleared);
}

#[test]
fn mcopy() {
    let bytecode = hex::decode(include_str!("contracts/MCOPYTest.hex")).unwrap();
    mcopy_test(bytecode);
}

fn mcopy_test(bytecode: Vec<u8>) {
    let contract = Address::new_id(100);

    let rt = util::init_construct_and_verify(bytecode, |rt| {
        rt.actor_code_cids.borrow_mut().insert(contract, *EVM_ACTOR_CODE_ID);
        rt.set_origin(contract);
    });

    // invoke contract

    let encoded_testdata = hex::decode("000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000087465737464617461000000000000000000000000000000000000000000000000").unwrap();

    let mut solidity_params = vec![];

    solidity_params.extend_from_slice(&hex::decode("73358055").unwrap()); // function selector, "optimizedCopy(bytes)"
    solidity_params.extend_from_slice(&encoded_testdata);

    let result = util::invoke_contract(&rt, &solidity_params);
    assert_eq!(&*result, &*encoded_testdata);
}

#[test]
fn bls_precompile() {
    let bytecode = hex::decode(include_str!("contracts/BLSPrecompile.hex")).unwrap();
    bls_precompile_test(bytecode);
}
fn bls_precompile_test(bytecode: Vec<u8>) {
    let contract = Address::new_id(100);
    let rt = util::init_construct_and_verify(bytecode, |rt| {
        rt.actor_code_cids.borrow_mut().insert(contract, *EVM_ACTOR_CODE_ID);
        rt.set_origin(contract);
    });

    // Test G1 Addition
    let mut solidity_params = vec![];
    solidity_params.extend_from_slice(&hex::decode("fa17c461").unwrap()); // function selector for "testG1Add()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &solidity_params);

    // Test G1 MSM
    let mut g1_msm_params = vec![];
    g1_msm_params.extend_from_slice(&hex::decode("6a3eee08").unwrap()); // function selector for "testG1MSM()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &g1_msm_params);

    // Test G2 Addition
    let mut g2_params = vec![];
    g2_params.extend_from_slice(&hex::decode("4660d8a1").unwrap()); // function selector for "testG2Add()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &g2_params);

    // Test G2 MSM
    let mut g2_msm_params = vec![];
    g2_msm_params.extend_from_slice(&hex::decode("fb0cc8d6").unwrap()); // function selector for "testG2MSM()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &g2_msm_params);

    // Test Map Fp to G1
    let mut map_fp_to_g1_params = vec![];
    map_fp_to_g1_params.extend_from_slice(&hex::decode("e38f2f12").unwrap()); // function selector for "testMapFpToG1()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &map_fp_to_g1_params);

    // Test Map Fp2 to G2
    let mut map_fp2_to_g2_params = vec![];
    map_fp2_to_g2_params.extend_from_slice(&hex::decode("f4f4dab1").unwrap()); // function selector for "testMapFp2ToG2()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &map_fp2_to_g2_params);

    // Test Pairing
    let mut pairing_params = vec![];
    pairing_params.extend_from_slice(&hex::decode("25a753ef").unwrap()); // function selector for "testPairing()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &pairing_params);

    // Test G1 Addition Failure
    let mut failure_params = vec![];
    failure_params.extend_from_slice(&hex::decode("3e6a10bc").unwrap()); // function selector for "testG1AddFailure()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &failure_params);

    // Test G2 Addition Failure
    let mut g2_failure_params = vec![];
    g2_failure_params.extend_from_slice(&hex::decode("ab7fa435").unwrap()); // function selector for "testG2AddFailure()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &g2_failure_params);

    // Test G1 MSM Failure
    let mut g1_msm_failure_params = vec![];
    g1_msm_failure_params.extend_from_slice(&hex::decode("0244cd8b").unwrap()); // function selector for "testG1MSMFailure()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &g1_msm_failure_params);

    // Test G2 MSM Failure
    let mut g2_msm_failure_params = vec![];
    g2_msm_failure_params.extend_from_slice(&hex::decode("0842daaf").unwrap()); // function selector for "testG2MSMFailure()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &g2_msm_failure_params);

    // Test Map Fp to G1 Failure
    let mut map_fp_to_g1_failure_params = vec![];
    map_fp_to_g1_failure_params.extend_from_slice(&hex::decode("df238759").unwrap()); // function selector for "testMapFpToG1Failure()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &map_fp_to_g1_failure_params);

    // Test Map Fp2 to G2 Failure
    let mut map_fp2_to_g2_failure_params = vec![];
    map_fp2_to_g2_failure_params.extend_from_slice(&hex::decode("1819ce68").unwrap()); // function selector for "testMapFp2ToG2Failure()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &map_fp2_to_g2_failure_params);

    // Test Pairing Failure
    let mut pairing_failure_params = vec![];
    pairing_failure_params.extend_from_slice(&hex::decode("513dc8b3").unwrap()); // function selector for "testPairingFailure()"

    rt.expect_gas_available(10_000_000_000u64);
    util::invoke_contract(&rt, &pairing_failure_params);
}
