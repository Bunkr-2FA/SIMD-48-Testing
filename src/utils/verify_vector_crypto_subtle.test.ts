import { verifyVector } from './verify_vector_crypto_subtle';


describe('verifyVector', () => {


    it('should verify a valid cryptographic vector', async () => {
        const vector = {
            x: "a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957",
            y: "5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b",
            r: "0000000000000000000000000000000000000000000000000000000000000005",
            s: "0000000000000000000000000000000000000000000000000000000000000001",
            msg: "313233343030",
            valid: true // This field is not used in the function but included for completeness
        };
        const result = await verifyVector(vector);
        expect(result).toBe(true);
    });

    it('should not verify an invalid cryptographic vector', async () => {
        const vector = {
            x: "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
            y: "c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
            r: "2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
            s: "b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
            msg: "313233343031",
            valid: false // This field is not used in the function but included for completeness
        };

        const result = await verifyVector(vector);
        expect(result).toBe(false);
    });
});
