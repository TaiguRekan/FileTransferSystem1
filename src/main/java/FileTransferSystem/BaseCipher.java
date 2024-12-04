package FileTransferSystem;

import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.security.SecureRandom;

public abstract class BaseCipher implements Cipherable {
    protected SecretKey secretKey;

    public BaseCipher(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    protected byte[] generateIV(int length) {
        byte[] iv = new byte[length];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }
}
