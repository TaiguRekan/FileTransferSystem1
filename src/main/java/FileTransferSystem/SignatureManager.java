package FileTransferSystem;

import java.security.*;

/**
 * Менеджер подписей, отвечающий за создание и верификацию цифровых подписей.
 */
public class SignatureManager {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    /**
     * Конструктор, который создает пару ключей (приватный и публичный).
     */
    public SignatureManager() {
        KeyPair keyPair = generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    /**
     * Конструктор, который принимает только публичный ключ.
     * @param publicKey Публиный ключ для верификации подписей.
     */
    public SignatureManager(PublicKey publicKey) {
        this.privateKey = null;
        this.publicKey = publicKey;
    }

    /**
     * Генерирует новую пару ключей RSA.
     * @return Пара ключей (приватный и публичный).
     */
    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Подписывает данные с использованием приватного ключа.
     * @param data Данные для подписи.
     * @return Подписанные данные.
     * @throws Exception Возможные ошибки при подписывании.
     */
    public byte[] signData(byte[] data) throws Exception {
        if (privateKey == null) {
            throw new IllegalStateException("Private key is not available for signing.");
        }
        Signature sig = Signature.getInstance("SHA256withRSA");
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
    public boolean verifySignature(byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    /**
     * Получает публичный ключ.
     * @return Публичный ключ.
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Получает приватный ключ.
     * @return Приватный ключ.
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Генерирует новую пару ключей.
     * @return Пара ключей (приватный и публичный).
     */
    public KeyPair getKeyPair() {
        return generateKeyPair();
    }
}
