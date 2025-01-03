package FileTransferSystem;

/**
 * Интерфейс для работы с цифровыми подписями.
 */
public interface Signatureable {

    /**
     * Подписывает данные.
     * @param data Данные для подписи.
     * @return Подписанная версия данных.
     * @throws Exception Возможные ошибки при подписывании.
     */
    byte[] sign(byte[] data) throws Exception;

    /**
     * Проверяет подпись данных.
     * @param data Данные, на которые была сделана подпись.
     * @param signature Подпись для верификации.
     * @return true, если подпись действительна, иначе false.
     * @throws Exception Возможные ошибки при верификации.
     */
    boolean verify(byte[] data, byte[] signature) throws Exception;
}
