import { PublicKey } from "@peculiar/x509";
import { KJUR } from "jsrsasign";

export namespace CryptoCompat {

    /**
     * Verifies the given signature for `data` using the given key and algorithm.
     */
    export function verify(
        algorithm: string,
        dataHex: string,
        key: PublicKey,
        signatureHex: string,
    ): boolean {
        // 1. Construct the Algorithm Name
        // jsrsasign requires "HASHwithKEYALGO" (e.g., "SHA256withECDSA" or "SHA256withRSA")
        // Node usually just takes "SHA256". You must append the key type.
        const algName = algorithm.toUpperCase() + "with" + (key.algorithm.name as string).toUpperCase(); 

        // 2. Initialize Signature
        const sig = new KJUR.crypto.Signature({ alg: algName });
        sig.init(key.toString());

        // 3. Pass the Data (Message)
        sig.updateHex(dataHex);

        // 4. Verify the Signature
        return sig.verify(signatureHex);
    }
}
