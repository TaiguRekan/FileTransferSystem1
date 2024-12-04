package FileTransferSystem;

public class SignatureableImpl implements Signatureable {
    /**
     * @param data
     * @return
     * @throws Exception
     */
    @Override
    public byte[] sign(byte[] data) throws Exception {
        return new byte[0];
    }

    /**
     * @param data
     * @param signature
     * @return
     * @throws Exception
     */
    @Override
    public boolean verify(byte[] data, byte[] signature) throws Exception {
        return false;
    }
}
