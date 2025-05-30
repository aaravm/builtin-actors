// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract BLSPrecompileCheck {
    address constant G1_ADD_PRECOMPILE = address(0x0B);
    // address constant G2_ADD_PRECOMPILE = address(0x0D);

    /// @notice Asserts that G1 addition precompile at 0x0B correctly computes 2·P
    function testG1Add() public view {
        bytes memory input = hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e100000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca942600000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a21";

        bytes memory EXPECTED_OUTPUT = hex"000000000000000000000000000000000a40300ce2dec9888b60690e9a41d3004fda4886854573974fab73b046d3147ba5b7a5bde85279ffede1b45b3918d82d0000000000000000000000000000000006d3d887e9f53b9ec4eb6cedf5607226754b07c01ace7834f57f3e7315faefb739e59018e22c492006190fba4a870025";
        bytes32 expectedHash = keccak256(EXPECTED_OUTPUT);

        // Call precompile
        (bool success, bytes memory output) = G1_ADD_PRECOMPILE.staticcall(input);
        require(success, "Precompile call failed");
        require(output.length == 128, "Invalid output length");
        bytes32 actualHash = keccak256(output);

        require(actualHash == expectedHash, "Unexpected output");
    }
    // TODO: Fix G2 addition precompile tests
    /*                                
    /// @notice Tests G2 addition precompile at 0x0C
    function testG2Add() public view {
        // First check if the precompile exists
        uint256 size;
        address addr = G2_ADD_PRECOMPILE;
        assembly {
            size := extcodesize(addr)
        }
        require(size > 0, "G2 precompile not found at address");

        // Encode input as two G2 points
        // Format: (x1_real, x1_imaginary, y1_real, y1_imaginary, x2_real, x2_imaginary, y2_real, y2_imaginary)
        bytes memory input = hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be00000000000000000000000000000000103121a2ceaae586d240843a398967325f8eb5a93e8fea99b62b9f88d8556c80dd726a4b30e84a36eeabaf3592937f2700000000000000000000000000000000086b990f3da2aeac0a36143b7d7c824428215140db1bb859338764cb58458f081d92664f9053b50b3fbd2e4723121b68000000000000000000000000000000000f9e7ba9a86a8f7624aa2b42dcc8772e1af4ae115685e60abc2c9b90242167acef3d0be4050bf935eed7c3b6fc7ba77e000000000000000000000000000000000d22c3652d0dc6f0fc9316e14268477c2049ef772e852108d269d9c38dba1d4802e8dae479818184c08f9a569d878451";

        bytes memory EXPECTED_OUTPUT = hex"000000000000000000000000000000000b54a8a7b08bd6827ed9a797de216b8c9057b3a9ca93e2f88e7f04f19accc42da90d883632b9ca4dc38d013f71ede4db00000000000000000000000000000000077eba4eecf0bd764dce8ed5f45040dd8f3b3427cb35230509482c14651713282946306247866dfe39a8e33016fcbe520000000000000000000000000000000014e60a76a29ef85cbd69f251b9f29147b67cfe3ed2823d3f9776b3a0efd2731941d47436dc6d2b58d9e65f8438bad073000000000000000000000000000000001586c3c910d95754fef7a732df78e279c3d37431c6a2b77e67a00c7c130a8fcd4d19f159cbeb997a178108fffffcbd20";
        bytes32 expectedHash = keccak256(EXPECTED_OUTPUT);

        // Call precompile with try/catch to get more error information
        (bool success, bytes memory output) = G2_ADD_PRECOMPILE.staticcall(input);
        
        if (!success) {
            if (output.length > 0) {
                // Try to decode the error message
                string memory errorMessage = abi.decode(output, (string));
                revert(string(abi.encodePacked("G2 add failed: ", errorMessage)));
            } else {
                revert("G2 add failed with no error message");
            }
        }
        
        require(output.length == 256, "Invalid G2 output length");
        bytes32 actualHash = keccak256(output);

        require(actualHash == expectedHash, "Unexpected G2 addition output");
    }
    */
    /// @notice Tests that G1 addition precompile returns an error for invalid inputs
    function testG1AddFailure() public view {
        // Input with invalid point (not on curve)
        bytes memory invalidInput = hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a2100000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca942600000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a21";
        
        // Call precompile, expecting failure
        (bool success, bytes memory output) = G1_ADD_PRECOMPILE.staticcall(invalidInput);
        
        // The precompile should fail for invalid points
        require(!success, "Precompile should fail for invalid input");
    }     
}