package FileTransferSystem;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class AESCipher extends BaseCipher {

    public AESCipher(SecretKey secretKey) {
        super(secretKey);
    }

    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        byte[] iv = generateIV(16); // IV для AES 16 байт
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
        byte[] encryptedBytes = cipher.doFinal(data);

        // Объединяем IV и зашифрованные данные
        return ByteBuffer.allocate(iv.length + encryptedBytes.length)
                .put(iv)
                .put(encryptedBytes)
                .array();
    }

    @Override
    public byte[] decrypt(byte[] data) throws Exception {
        byte[] iv = new byte[16]; // IV для AES 16 байт
        System.arraycopy(data, 0, iv, 0, iv.length);
        byte[] encryptedData = new byte[data.length - iv.length];
        System.arraycopy(data, iv.length, encryptedData, 0, encryptedData.length);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
        return cipher.doFinal(encryptedData);
    }
}
