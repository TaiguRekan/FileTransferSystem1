package FileTransferSystem;

import org.apache.log4j.Logger;
import org.apache.log4j.LogManager;

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

    public GUI() {
        JFrame frame = new JFrame("Отправка файлов");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 350);

        ipField = new JTextField(15);
        filePathField = new JTextField(15);
        algorithmComboBox = new JComboBox<>(new String[]{"AES", "DES"});
        signatureAlgorithmComboBox = new JComboBox<>(new String[]{"SHA256withRSA", "SHA384withRSA"});
        sendButton = new JButton("Отправить файл");
        signatureArea = new JTextArea(5, 30);
        signatureArea.setLineWrap(true);
        signatureArea.setWrapStyleWord(true);
        signatureArea.setEditable(false);

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(7, 2));
        panel.add(new JLabel("IP-адрес сервера:"));
        panel.add(ipField);
        panel.add(new JLabel("Путь к файлу:"));
        panel.add(filePathField);
        panel.add(new JLabel("Алгоритм шифрования:"));
        panel.add(algorithmComboBox);
        panel.add(new JLabel("Алгоритм подписи:"));
        panel.add(signatureAlgorithmComboBox);
        panel.add(new JLabel());
        panel.add(sendButton);

        sendButton.addActionListener(this::sendFile);

        frame.getContentPane().add(panel);
        frame.setVisible(true);
    }

    private void sendFile(ActionEvent e) {
        String serverAddress = ipField.getText();
        String filePath = filePathField.getText();
        String encryptionAlgorithm = Objects.requireNonNull(algorithmComboBox.getSelectedItem()).toString();
        String signatureAlgorithm = Objects.requireNonNull(signatureAlgorithmComboBox.getSelectedItem()).toString();

        File file = new File(filePath);
        if (!file.exists() || file.isDirectory()) {
            JOptionPane.showMessageDialog(null, "Файл не найден или это директория.", "Ошибка", JOptionPane.ERROR_MESSAGE);
            logger.error("Файл не найден или это директория: " + filePath);
            return;
        }

        try (Socket socket = new Socket(serverAddress, 12345);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             FileInputStream fis = new FileInputStream(file)) {

            logger.info("Подключение к серверу...");
            signatureManager = new SignatureManager();
            KeyPair keyPair = signatureManager.getKeyPair();

            byte[] fileBytes = fis.readAllBytes();
            SecretKey secretKey = generateSecretKey(encryptionAlgorithm);
            byte[] encryptedData = encryptFile(fileBytes, secretKey, encryptionAlgorithm);

            // Извлечение IV
            byte[] iv = new byte[encryptionAlgorithm.equals("DES") ? 8 : 16];
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);

            // Создание конструкции для хэширования: IV + зашифрованные данные
            byte[] dataToHash = new byte[iv.length + encryptedData.length];
            System.arraycopy(iv, 0, dataToHash, 0, iv.length);
            System.arraycopy(encryptedData, 0, dataToHash, iv.length, encryptedData.length);

            // Подписание хеша выбранным алгоритмом
            byte[] fileHash = generateHash(dataToHash);
            byte[] signature = signWithSelectedAlgorithm(fileHash, signatureAlgorithm);
            signatureArea.setText(bytesToHex(signature));

            // Отправляем имя файла
            out.writeUTF(file.getName());
            // Отправляем размер файла
            out.writeLong(encryptedData.length);
            // Отправляем алгоритм шифрования
            out.writeUTF(encryptionAlgorithm);
            // Отправляем симметричный ключ
            out.write(secretKey.getEncoded());
            // Отправляем открытый ключ клиента
            byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
            out.writeInt(publicKeyBytes.length);
            out.write(publicKeyBytes);
            // Отправляем подпись
            out.write(signature);
            // Отправляем зашифрованные данные
            out.write(encryptedData);

            JOptionPane.showMessageDialog(null, "Файл успешно отправлен (шифрованный).", "Успех", JOptionPane.INFORMATION_MESSAGE);
            logger.info("Файл успешно отправлен: " + file.getName());
        } catch (Exception e1) {
            JOptionPane.showMessageDialog(null, "Ошибка: " + e1.getMessage(), "Ошибка", JOptionPane.ERROR_MESSAGE);
            logger.error("Ошибка: " + e1.getMessage(), e1);
        }
    }

    private byte[] signWithSelectedAlgorithm(byte[] data, String algorithm) throws Exception {
        switch (algorithm) {
            case "SHA256withRSA":
                return signatureManager.signData(data);
            case "SHA384withRSA":
                return new SHA384Signature(signatureManager.getPrivateKey(), signatureManager.getPublicKey()).sign(data);
            default:
                throw new IllegalArgumentException("Неизвестный алгоритм подписи: " + algorithm);
        }
    }

    private SecretKey generateSecretKey(String algorithm) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        keyGen.init(algorithm.equals("DES") ? 56 : 128);
        return keyGen.generateKey();
    }

    private byte[] generateHash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    private byte[] encryptFile(byte[] fileBytes, SecretKey secretKey, String algorithm) throws Exception {
        byte[] iv = new byte[algorithm.equals("DES") ? 8 : 16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
        byte[] encryptedBytes = cipher.doFinal(fileBytes);

        // Добавляем IV к зашифрованным данным
        byte[] encryptedData = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, encryptedData, iv.length, encryptedBytes.length);
        return encryptedData;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
