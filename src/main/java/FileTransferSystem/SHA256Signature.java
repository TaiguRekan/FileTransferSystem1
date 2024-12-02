package FileTransferSystem;

import java.security.*;

public class SHA256Signature extends BaseSignature {

    public SHA256Signature(PrivateKey privateKey, PublicKey publicKey) {
        super(privateKey, publicKey);
    }

    @Override
    public byte[] sign(byte[] data) throws Exception {
        if (privateKey == null) {
            throw new IllegalStateException("Private key is not available for signing.");
        }
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    @Override
    public boolean verify(byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }
}
