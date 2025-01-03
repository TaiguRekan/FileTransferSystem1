package FileTransferSystem;

import java.security.*;

/**
 * Класс для подписи данных с использованием алгоритма SHA-384 и RSA.
 */
public class SHA384Signature extends BaseSignature {

    /**
     * Конструктор класса SHA384Signature.
     * @param privateKey Приватный ключ для подписи.
     * @param publicKey Публичный ключ для верификации подписи.
     */
    public SHA384Signature(PrivateKey privateKey, PublicKey publicKey) {
        super(privateKey, publicKey);
    }

    /**
     * Подписывает данные с использованием приватного ключа.
     * @param data Данные для подписи.
     * @return Подпись.
     * @throws Exception Возможные ошибки при подписывании.
     */
    @Override
    public byte[] sign(byte[] data) throws Exception {
        if (privateKey == null) {
            throw new IllegalStateException("Private key is not available for signing.");
        }
        Signature sig = Signature.getInstance("SHA384withRSA");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    /**
     * Проверяет подпись данных с использованием публичного ключа.
     * @param data Данные, на которые была сделана подпись.
     * @param signature Подпись для верификации.
     * @return true, если подпись действительна, иначе false.
     * @throws Exception Возможные ошибки при верификации.
     */
    @Override
    public boolean verify(byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA384withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }
}
