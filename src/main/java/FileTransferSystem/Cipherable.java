package FileTransferSystem;

/**
 * Интерфейс для шифрования и дешифрования данных.
 */
public interface Cipherable {
    /**
     * Метод для шифрования данных.
     * @param data Данные для шифрования.
     * @return Зашифрованные данные.
     * @throws Exception Возможные ошибки при шифровании.
     */
    byte[] encrypt(byte[] data) throws Exception;

    /**
     * Метод для дешифрования данных.
     * @param data Данные для дешифрования.
     * @return Расшифрованные данные.
     * @throws Exception Возможные ошибки при дешифровании.
     */
    byte[] decrypt(byte[] data) throws Exception;
}