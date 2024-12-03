package FileTransferSystem;

public interface Signatureable {
    byte[] sign(byte[] data) throws Exception;
    boolean verify(byte[] data, byte[] signature) throws Exception;
}
