use crate::interpreter::{
    System,
    precompiles::{
        PrecompileContext, PrecompileError, PrecompileResult,
        bls_util::{SCALAR_LENGTH_BITS, is_infinity, p1_scalar_mul, p1_to_affine},
    },
};
use fil_actors_runtime::runtime::Runtime;

use crate::interpreter::precompiles::bls_util::{
    G1_MSM_INPUT_LENGTH, G1_OUTPUT_LENGTH, PADDED_G1_LENGTH, encode_g1_point, extract_g1_input,
    read_scalar,
};

use blst::{MultiPoint, blst_p1_affine, blst_scalar};

/// **BLS12_G1MSM Precompile**
///
/// Implements G1 multi-scalar multiplication (MSM) according to [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#abi-for-g1-multiexponentiation).
/// The input is expected to be `160 * k` bytes, where each 160-byte segment consists of:
/// - A 128-byte encoding of a G1 point (padded, in affine form)
/// - A 32-byte encoding of a scalar value in Big-Endian
///
/// The output is an encoding of a single G1 point (128 bytes).
pub fn bls12_g1msm<RT: Runtime>(
    _: &mut System<RT>,
    input: &[u8],
    _: PrecompileContext,
) -> PrecompileResult {
    // Validate that the input length is non-zero and an exact multiple of the per-pair length.
    let input_len = input.len();
    if input.is_empty() || input_len % G1_MSM_INPUT_LENGTH != 0 {
        return Err(PrecompileError::IncorrectInputSize);
    }

    // Determine the number of (point, scalar) pairs.
    let k = input_len / G1_MSM_INPUT_LENGTH;
    let mut g1_points: Vec<blst_p1_affine> = Vec::with_capacity(k);
    let mut scalars: Vec<blst_scalar> = Vec::with_capacity(k);

    // Process each (point, scalar) pair.
    for chunk in input.chunks_exact(G1_MSM_INPUT_LENGTH) {
        let (encoded_point, encoded_scalar) = chunk.split_at(PADDED_G1_LENGTH);

        // Deserialize the point (performing subgroup check).
        let point_aff = extract_g1_input(encoded_point, true)?;

        // Optimization: skip this pair if the deserialized point represents infinity.
        if is_infinity(&point_aff) {
            continue;
        }

        // Skip this pair if the scalar encoding is zero.
        if encoded_scalar.iter().all(|&b| b == 0) {
            continue;
        }

        g1_points.push(point_aff);
        scalars.push(read_scalar(encoded_scalar)?);
    }

    // If no valid (point, scalar) pairs remain, return the encoded point at infinity.
    if g1_points.is_empty() {
        return Ok(vec![0u8; G1_OUTPUT_LENGTH]);
    }

    // Compute the MSM and convert the projective result back to affine form.
    let result_aff = p1_msm(g1_points, scalars);
    Ok(encode_g1_point(&result_aff))
}

/// Performs multi-scalar multiplication (MSM) for G1 points.
///
/// Given vectors of G1 points and corresponding scalars, returns their weighted sum.
/// If a single (point, scalar) pair is provided, a simple scalar multiplication is used.
///
/// # Panics
///
/// Panics if the number of points does not equal the number of scalars.
#[inline]
pub(super) fn p1_msm(g1_points: Vec<blst_p1_affine>, scalars: Vec<blst_scalar>) -> blst_p1_affine {
    assert_eq!(
        g1_points.len(),
        scalars.len(),
        "Number of scalars must equal the number of G1 points"
    );

    if g1_points.len() == 1 {
        return p1_scalar_mul(&g1_points[0], &scalars[0]);
    }

    // Flatten the scalars into a contiguous byte vector.
    let scalars_bytes: Vec<u8> = scalars.into_iter().flat_map(|s| s.b).collect();

    // Perform multi-scalar multiplication using the blst MultiPoint interface.
    let multiexp_proj = g1_points.mult(&scalars_bytes, SCALAR_LENGTH_BITS);

    // Convert the projective result back to affine form.
    p1_to_affine(&multiexp_proj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interpreter::System;
    use fil_actors_runtime::test_utils::MockRuntime;
    use hex_literal::hex;
    use substrate_bn::CurveError;

    #[test]
    fn test_g1_msm_success() {
        let rt = MockRuntime::default();
        rt.in_call.replace(true);
        let mut system = System::create(&rt).unwrap();
        use hex_literal::hex;

        // Array of tuples: (input, expected)
        let test_vectors = [
            (
                // bls_g1msm_(g1+g1=2*g1)
                hex!(
                    "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000000000000000000000000000000000002"
                ),
                hex!(
                    "000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28"
                ),
            ),
            (
                // bls_g1msm_(p1+p1=2*p1)
                hex!(
                    "00000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca942600000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a210000000000000000000000000000000000000000000000000000000000000002"
                ),
                hex!(
                    "0000000000000000000000000000000015222cddbabdd764c4bee0b3720322a65ff4712c86fc4b1588d0c209210a0884fa9468e855d261c483091b2bf7de6a630000000000000000000000000000000009f9edb99bc3b75d7489735c98b16ab78b9386c5f7a1f76c7e96ac6eb5bbde30dbca31a74ec6e0f0b12229eecea33c39"
                ),
            ),
            (
                // bls_g1msm_(1*g1=g1)
                hex!(
                    "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000000000000000000000000000000000001"
                ),
                hex!(
                    "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
                ),
            ),
            (
                // bls_g1msm_(1*p1=p1)
                hex!(
                    "00000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca942600000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a210000000000000000000000000000000000000000000000000000000000000001"
                ),
                hex!(
                    "00000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca942600000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a21"
                ),
            ),
            (
                // bls_g1msm_(0*g1=inf)
                hex!(
                    "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000000000000000000000000000000000000"
                ),
                hex!(
                    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                ),
            ),
            (
                // bls_g1msm_(0*p1=inf)
                hex!(
                    "00000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca942600000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a210000000000000000000000000000000000000000000000000000000000000000"
                ),
                hex!(
                    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                ),
            ),
        ];

        for (input, expected) in test_vectors.iter() {
            let res = bls12_g1msm(&mut system, input, PrecompileContext::default())
                .expect("g1 msm should succeed");
            assert_eq!(res, *expected, "g1 msm result mismatch");
        }
    }
    #[test]
    fn test_g1_msm_success_2() {
        let rt = MockRuntime::default();
        rt.in_call.replace(true);
        let mut system = System::create(&rt).unwrap();

        // Test case 1: bls_g1msm_random*g1_unnormalized_scalar
        let input1 = hex!(
            "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e19a2b64cc58f8992cb21237914262ca9ada6cb13dc7b7d3f11c278fe0462040e4"
        );

        let expected1 = hex!(
            "000000000000000000000000000000000491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a0000000000000000000000000000000017cd7061575d3e8034fcea62adaa1a3bc38dca4b50e4c5c01d04dd78037c9cee914e17944ea99e7ad84278e5d49f36c4"
        );

        let res1 = bls12_g1msm(&mut system, &input1, PrecompileContext::default())
            .expect("g2 msm should succeed");
        assert_eq!(res1, expected1, "bls_g2msm_multiple result mismatch");

        // Test case 2: bls_g1msm_multiple
        let input2 = hex!(
            "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e300000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca942600000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a2147b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff66513800000000000000000000000000000000184bb665c37ff561a89ec2122dd343f20e0f4cbcaec84e3c3052ea81d1834e192c426074b02ed3dca4e7676ce4ce48ba0000000000000000000000000000000004407b8d35af4dacc809927071fc0405218f1401a6d15af775810e4e460064bcc9468beeba82fdc751be70476c888bf3328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d21600000000000000000000000000000000009769f3ab59bfd551d53a5f846b9984c59b97d6842b20a2c565baa167945e3d026a3755b6345df8ec7e6acb6868ae6d000000000000000000000000000000001532c00cf61aa3d0ce3e5aa20c3b531a2abd2c770a790a2613818303c6b830ffc0ecf6c357af3317b9575c567f11cd2c263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e2000000000000000000000000000000001974dbb8e6b5d20b84df7e625e2fbfecb2cdb5f77d5eae5fb2955e5ce7313cae8364bc2fff520a6c25619739c6bdcb6a0000000000000000000000000000000015f9897e11c6441eaa676de141c8d83c37aab8667173cbe1dfd6de74d11861b961dccebcd9d289ac633455dfcc7013a347b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665131000000000000000000000000000000000a7a047c4a8397b3446450642c2ac64d7239b61872c9ae7a59707a8f4f950f101e766afe58223b3bff3a19a7f754027c000000000000000000000000000000001383aebba1e4327ccff7cf9912bda0dbc77de048b71ef8c8a81111d71dc33c5e3aa6edee9cf6f5fe525d50cc50b77cc9328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d211000000000000000000000000000000000e7a16a975904f131682edbb03d9560d3e48214c9986bd50417a77108d13dc957500edf96462a3d01e62dc6cd468ef11000000000000000000000000000000000ae89e677711d05c30a48d6d75e76ca9fb70fe06c6dd6ff988683d89ccde29ac7d46c53bb97a59b1901abf1db66052db55b53c4669f19f0fc7431929bc0363d7d8fb432435fcde2635fdba334424e9f5"
        );

        let expected2 = hex!(
            "00000000000000000000000000000000053fbdb09b6b5faa08bfe7b7069454247ad4d8bd57e90e2d2ebaa04003dcf110aa83072c07f480ab2107cca2ccff6091000000000000000000000000000000001654537b7c96fe64d13906066679c3d45808cb666452b55d1b909c230cc4b423c3f932c58754b9b762dc49fcc825522c"
        );
        let res2 = bls12_g1msm(&mut system, &input2, PrecompileContext::default())
            .expect("g2 msm should succeed");
        assert_eq!(res2, expected2, "bls_g2msm_random*g2_unnormalized_scalar result mismatch");

        // Test case 3: bls_g1msm_multiple_with_point_at_infinity
        let input3 = hex!(
            "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e300000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca942600000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a2147b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff66513800000000000000000000000000000000184bb665c37ff561a89ec2122dd343f20e0f4cbcaec84e3c3052ea81d1834e192c426074b02ed3dca4e7676ce4ce48ba0000000000000000000000000000000004407b8d35af4dacc809927071fc0405218f1401a6d15af775810e4e460064bcc9468beeba82fdc751be70476c888bf3328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d21600000000000000000000000000000000009769f3ab59bfd551d53a5f846b9984c59b97d6842b20a2c565baa167945e3d026a3755b6345df8ec7e6acb6868ae6d000000000000000000000000000000001532c00cf61aa3d0ce3e5aa20c3b531a2abd2c770a790a2613818303c6b830ffc0ecf6c357af3317b9575c567f11cd2c263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e2000000000000000000000000000000001974dbb8e6b5d20b84df7e625e2fbfecb2cdb5f77d5eae5fb2955e5ce7313cae8364bc2fff520a6c25619739c6bdcb6a0000000000000000000000000000000015f9897e11c6441eaa676de141c8d83c37aab8667173cbe1dfd6de74d11861b961dccebcd9d289ac633455dfcc7013a347b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665131000000000000000000000000000000000a7a047c4a8397b3446450642c2ac64d7239b61872c9ae7a59707a8f4f950f101e766afe58223b3bff3a19a7f754027c000000000000000000000000000000001383aebba1e4327ccff7cf9912bda0dbc77de048b71ef8c8a81111d71dc33c5e3aa6edee9cf6f5fe525d50cc50b77cc9328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d21100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e7a16a975904f131682edbb03d9560d3e48214c9986bd50417a77108d13dc957500edf96462a3d01e62dc6cd468ef11000000000000000000000000000000000ae89e677711d05c30a48d6d75e76ca9fb70fe06c6dd6ff988683d89ccde29ac7d46c53bb97a59b1901abf1db66052db55b53c4669f19f0fc7431929bc0363d7d8fb432435fcde2635fdba334424e9f5"
        );
        let expected3 = hex!(
            "00000000000000000000000000000000053fbdb09b6b5faa08bfe7b7069454247ad4d8bd57e90e2d2ebaa04003dcf110aa83072c07f480ab2107cca2ccff6091000000000000000000000000000000001654537b7c96fe64d13906066679c3d45808cb666452b55d1b909c230cc4b423c3f932c58754b9b762dc49fcc825522c"
        );
        let res3 = bls12_g1msm(&mut system, &input3, PrecompileContext::default())
            .expect("g2 msm should succeed");
        assert_eq!(res3, expected3, "bls_g2msm_multiple_with_point_at_infinity result mismatch");
    }
    #[test]
    fn test_g1_msm_failure() {
        let rt = MockRuntime::default();
        rt.in_call.replace(true);
        let mut system = System::create(&rt).unwrap();
        let ctx = PrecompileContext::default();

        // Test: Empty input
        let res = bls12_g1msm(&mut system, &[], ctx);
        assert!(matches!(res, Err(PrecompileError::IncorrectInputSize)));

        // Test: Short input
        let short_input = hex::decode(
            "00000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\
            0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1\
            0000000000000000000000000000000000000000000000000000000000000002"
        ).unwrap();
        let res = bls12_g1msm(&mut system, &short_input, ctx);
        assert!(matches!(res, Err(PrecompileError::IncorrectInputSize)));

        // // Test: Invalid field element
        let invalid_field = hex::decode(
            "0000000000000000000000000000000031f2e5916b17be2e71b10b4292f558e727dfd7d48af9cbc5087f0ce00dcca27c8b01e83eaace1aefb539f00adb2271660000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e10000000000000000000000000000000000000000000000000000000000000002"
        ).unwrap();
        let res = bls12_g1msm(&mut system, &invalid_field, ctx);
        assert!(matches!(res, Err(PrecompileError::EcErr(CurveError::NotMember))));

        // Test: Point not on curve
        let not_on_curve = hex::decode(
            "0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\
            00000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a21\
            0000000000000000000000000000000000000000000000000000000000000002"
        ).unwrap();
        let res = bls12_g1msm(&mut system, &not_on_curve, ctx);
        assert!(matches!(res, Err(PrecompileError::EcErr(CurveError::NotMember))));

        // Test: Invalid top bytes
        let invalid_top = hex::decode(
            "1000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\
            0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1\
            0000000000000000000000000000000000000000000000000000000000000002"
        ).unwrap();
        let res = bls12_g1msm(&mut system, &invalid_top, ctx);
        assert!(matches!(res, Err(PrecompileError::InvalidInput)));

        // Test: Point not in correct subgroup
        let not_in_subgroup = hex::decode(
            "000000000000000000000000000000000123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00000000000000000000000000000000193fb7cedb32b2c3adc06ec11a96bc0d661869316f5e4a577a9f7c179593987beb4fb2ee424dbb2f5dd891e228b46c4a0000000000000000000000000000000000000000000000000000000000000002"
        ).unwrap();
        let res = bls12_g1msm(&mut system, &not_in_subgroup, ctx);
        assert!(matches!(res, Err(PrecompileError::InvalidInput)));
    }
}
