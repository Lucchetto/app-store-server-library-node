import { X509Certificate as X509CertificateNode } from 'crypto';
import { PublicKey, X509Certificate as X509CertificatePeculiar } from '@peculiar/x509';
import { Crypto } from "@peculiar/webcrypto";

export namespace X509CertificateCompat {

    /**
     * Verifies that this certificate was signed by the given root certificate's public key.
     * Does not perform any other validation checks on the certificate.
     */
    export async function verify(intermediate: X509CertificateNode, root: X509CertificateNode): Promise<boolean> {
        const crypto = new Crypto();
        const rootPeculiar = new X509CertificatePeculiar(root.raw);
        const intermediatePeculiar = new X509CertificatePeculiar(intermediate.raw);

        // Get the public key of the issuer
        const issuerKey = rootPeculiar.publicKey; 

        // Verify (returns a Promise<boolean>)
        return await intermediatePeculiar.verify({ publicKey: issuerKey, signatureOnly: true }, crypto)
    }

    /**
     * The public key for this certificate as a {@link PublicKey} object
     */
    export function publicKey(certificate: X509CertificateNode): PublicKey {
        const certPeculiar = new X509CertificatePeculiar(certificate.raw);

        return certPeculiar.publicKey;
    }
}
