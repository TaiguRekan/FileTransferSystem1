package FileTransferSystem;

import java.security.PrivateKey;
import java.security.PublicKey;


public abstract class BaseSignature implements Signatureable {
    protected PrivateKey privateKey;
    protected PublicKey publicKey;

    public BaseSignature(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
}
