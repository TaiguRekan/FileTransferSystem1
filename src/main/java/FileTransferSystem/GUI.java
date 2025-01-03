package FileTransferSystem;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Класс графического интерфейса для отправки файлов.
 */
public class GUI {
    private SignatureManager signatureManager;
    private JTextField ipField;
    private JTextField filePathField;
    private JComboBox<String> algorithmComboBox;
    private JComboBox<String> signatureAlgorithmComboBox;
    private JButton sendButton;
    private JTextArea signatureArea;
    private static final Logger logger = LogManager.getLogger(GUI.class);

    public static void main(String[] args) {
        SwingUtilities.invokeLater(GUI::new);
    }

    /**
     * Конструктор графического интерфейса для отправки файлов.
     */
    public GUI() {
        JFrame frame = new JFrame("File Sender");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 350);

        ipField = new JTextField(15);
        filePathField = new JTextField(15);
        algorithmComboBox = new JComboBox<>(new String[]{"AES", "DES"});
        signatureAlgorithmComboBox = new JComboBox<>(new String[]{"SHA256withRSA", "SHA384withRSA"});
        sendButton = new JButton("Send File");
        signatureArea = new JTextArea(5, 30);
        signatureArea.setLineWrap(true);
        signatureArea.setWrapStyleWord(true);
        signatureArea.setEditable(false);

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(7, 2));
        panel.add(new JLabel("Server IP Address:"));
        panel.add(ipField);
        panel.add(new JLabel("File Path:"));
        panel.add(filePathField);
        panel.add(new JLabel("Encryption Algorithm:"));
        panel.add(algorithmComboBox);
        panel.add(new JLabel("Signature Algorithm:"));
        panel.add(signatureAlgorithmComboBox);
        panel.add(new JLabel());
        panel.add(sendButton);

        sendButton.addActionListener(this::sendFile);

        frame.getContentPane().add(panel);
        frame.setVisible(true);
    }

    /**
     * Отправляет файл на сервер.
     * @param e Действие кнопки отправки.
     */
    private void sendFile(ActionEvent e) {
        String serverAddress = ipField.getText();
        String filePath = filePathField.getText();
        String encryptionAlgorithm = Objects.requireNonNull(algorithmComboBox.getSelectedItem()).toString();
        String signatureAlgorithm = Objects.requireNonNull(signatureAlgorithmComboBox.getSelectedItem()).toString();

        File file = new File(filePath);
        if (!file.exists() || file.isDirectory()) {
            JOptionPane.showMessageDialog(null, "File not found or it is a directory.", "Error", JOptionPane.ERROR_MESSAGE);
            logger.error("File not found or it is a directory: " + filePath);
            return;
        }

        try (Socket socket = new Socket(serverAddress, 12345);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             FileInputStream fis = new FileInputStream(file)) {

            logger.info("Connecting to server...");
            signatureManager = new SignatureManager();
            KeyPair keyPair = signatureManager.getKeyPair();

            byte[] fileBytes = fis.readAllBytes();
            SecretKey secretKey = generateSecretKey(encryptionAlgorithm);
            byte[] encryptedData = encryptFile(fileBytes, secretKey, encryptionAlgorithm);

            // Extracting IV
            byte[] iv = new byte[encryptionAlgorithm.equals("DES") ? 8 : 16];
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);

            // Create hash data: IV + encrypted data
            byte[] dataToHash = new byte[iv.length + encryptedData.length];
            System.arraycopy(iv, 0, dataToHash, 0, iv.length);
            System.arraycopy(encryptedData, 0, dataToHash, iv.length, encryptedData.length);

            // Signing the hash with the selected algorithm
            byte[] fileHash = generateHash(dataToHash);
            byte[] signature = signWithSelectedAlgorithm(fileHash, signatureAlgorithm);
            signatureArea.setText(bytesToHex(signature));

            // Send file name
            out.writeUTF(file.getName());
            // Send file size
            out.writeLong(encryptedData.length);
            // Send encryption algorithm
            out.writeUTF(encryptionAlgorithm);
            // Send symmetric key
            out.write(secretKey.getEncoded());
            // Send client's public key
            byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
            out.writeInt(publicKeyBytes.length);
            out.write(publicKeyBytes);
            // Send signature
            out.write(signature);
            // Send encrypted data
            out.write(encryptedData);

            JOptionPane.showMessageDialog(null, "File successfully sent (encrypted).", "Success", JOptionPane.INFORMATION_MESSAGE);
            logger.info("File successfully sent: " + file.getName());
        } catch (Exception e1) {
            JOptionPane.showMessageDialog(null, "Error: " + e1.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            logger.error("Error: " + e1.getMessage(), e1);
        }
    }

    /**
     * Подписывает данные с использованием принятого алгоритма.
     * @param data Данные для подписи.
     * @param algorithm Алгоритм подписи.
     * @return Подпись.
     * @throws Exception Возможные ошибки при подписывании.
     */
    private byte[] signWithSelectedAlgorithm(byte[] data, String algorithm) throws Exception {
        switch (algorithm) {
            case "SHA256withRSA":
                return signatureManager.signData(data);
            case "SHA384withRSA":
                return new SHA384Signature(signatureManager.getPrivateKey(), signatureManager.getPublicKey()).sign(data);
            default:
                throw new IllegalArgumentException("Unknown signing algorithm: " + algorithm);
        }
    }

    /**
     * Генерирует секретный ключ для шифрования.
     * @param algorithm Алгоритм шифрования.
     * @return Секретный ключ.
     * @throws Exception Возможные ошибки при генерации ключа.
     */
    private SecretKey generateSecretKey(String algorithm) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        keyGen.init(algorithm.equals("DES") ? 56 : 128);
        return keyGen.generateKey();
    }

    /**
     * Генерирует хэш для данных.
     * @param data Данные для хэширования.
     * @return Хэшированные данные.
     * @throws Exception Возможные ошибки при хэшировании.
     */
    private byte[] generateHash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    /**
     * Шифрует файл.
     * @param fileBytes Байтовые данные файла.
     * @param secretKey Секретный ключ для шифрования.
     * @param algorithm Алгоритм шифрования.
     * @return Зашифрованные данные.
     * @throws Exception Возможные ошибки при шифровании.
     */
    private byte[] encryptFile(byte[] fileBytes, SecretKey secretKey, String algorithm) throws Exception {
        byte[] iv = new byte[algorithm.equals("DES") ? 8 : 16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
        byte[] encryptedBytes = cipher.doFinal(fileBytes);

        // Add IV to encrypted data
        byte[] encryptedData = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, encryptedData, iv.length, encryptedBytes.length);
        return encryptedData;
    }

    /**
     * Преобразует байтовый массив в строку шестнадцатеричных значений.
     * @param bytes Байт массив.
     * @return Шестнадцатеричная строка.
     */
    private String bytesToHex(byte[] bytes) {
        return IntStream.range(0, bytes.length)
                .mapToObj(i -> String.format("%02x", bytes[i]))
                .collect(Collectors.joining());
    }
}
