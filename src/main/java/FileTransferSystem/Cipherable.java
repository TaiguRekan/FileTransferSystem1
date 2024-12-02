package FileTransferSystem;

public interface Cipherable {
    byte[] encrypt(byte[] data) throws Exception;
    byte[] decrypt(byte[] data) throws Exception;
}
