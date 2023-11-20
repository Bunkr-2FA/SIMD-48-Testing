import { createPublicKeyPem, uncompressedPublicKeyHex, derFromRS} from "./create_pem_pubkey";

describe('Public Key Tests', () => {
    // Test for uncompressed public key hex string with padding
    it("Test creation of uncompressed public key hex string", () => {
        const x = "0ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103";
        const y = "00c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e";
        const expectedHex = "040ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e";
        expect(uncompressedPublicKeyHex(x, y)).toBe(expectedHex);
    });

    // Test for uncompressed public key hex string with no padding
    it("Test creation of uncompressed public key hex string", () => {
        const x = "ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103";
        const y = "c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e";
        const expectedHex = "040ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e";
        expect(uncompressedPublicKeyHex(x, y)).toBe(expectedHex);
    });

    // Test for uncompressed public key hex string with too much padding
    it("Test creation of uncompressed public key hex string", () => {
        const x = "000ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103";
        const y = "0000c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e";
        const expectedHex = "040ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e";
        expect(uncompressedPublicKeyHex(x, y)).toBe(expectedHex);
    });

    // Test for public key in PEM format
    it("Test creation of a public key in PEM format", () => {
        const x = "0ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103";
        const y = "00c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e";
        const expectedPem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECtmVACiNRmlAAx1yqfVEWk1DeEZA\nhVvwpph00t5f4QPFAR5u8sQtzVDV09Kfma5uuiyAySRPTFQi8Jef8MO6Xg==\n-----END PUBLIC KEY-----";
        expect(createPublicKeyPem(x, y)).toBe(expectedPem);
    });

    it('correctly encodes r and s into signature in DER format', () => {
        // Example test case
        const rHex = "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18";
        const sHex = "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db";
        const expectedDer = "304502202ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18022100b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db";

        const result = derFromRS(rHex, sHex);
        expect(result).toBe(expectedDer);
    });


});
