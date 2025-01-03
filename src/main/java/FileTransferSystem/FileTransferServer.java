package FileTransferSystem;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.stream.IntStream;

/**
 * Класс сервера для передачи файлов.
 */
public class FileTransferServer {
    private static final int SIGNATURE_LENGTH = 256;
    private static volatile boolean running = false;
    private static JTextArea logArea;
    private static final Logger logger = LogManager.getLogger(FileTransferServer.class);

    public static void main(String[] args) {
        SwingUtilities.invokeLater(FileTransferServer::createAndShowGUI);
    }

    /**
     * Создает и отображает GUI для сервера.
     */
    private static void createAndShowGUI() {
        JFrame frame = new JFrame("File Transfer Server");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);
        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);
        frame.add(scrollPane, BorderLayout.CENTER);
        JPanel buttonPanel = new JPanel();

        JButton startButton = new JButton("Start Server");
        JButton stopButton = new JButton("Stop Server");
        stopButton.setEnabled(false);

        startButton.addActionListener(e -> {
            startServer();
            startButton.setEnabled(false);
            stopButton.setEnabled(true);
        });

        stopButton.addActionListener(e -> {
            stopServer();
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
        });

        buttonPanel.add(startButton);
        buttonPanel.add(stopButton);
        frame.add(buttonPanel, BorderLayout.SOUTH);
        frame.setVisible(true);
    }

    /**
     * Запускает сервер для получения файлов.
     */
    private static void startServer() {
        running = true;
        new Thread(() -> {
            int port = 12345;
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                log("Server started and waiting for connections...");
                logger.info("Server started and waiting for connections...");
                while (running) {
                    try (Socket socket = serverSocket.accept();
                         DataInputStream in = new DataInputStream(socket.getInputStream())) {
                        log("Client connected: " + socket.getInetAddress().getHostAddress());
                        logger.info("Client connected: " + socket.getInetAddress().getHostAddress());
                        receiveFile(in);
                    } catch (IOException e) {
                        if (running) {
                            log("Error: " + e.getMessage());
                            logger.error("Error: " + e.getMessage(), e);
                        }
                    }
                }
            } catch (IOException e) {
                log("Error while starting server: " + e.getMessage());
                logger.error("Error while starting server: " + e.getMessage(), e);
            }
        }).start();
    }

    /**
     * Останавливает сервер.
     */
    private static void stopServer() {
        running = false;
        log("Server stopped.");
        logger.info("Server stopped.");
    }

    /**
     * Записывает сообщение в текстовую область логов.
     * @param message Сообщение для записи.
     */
    private static void log(String message) {
        logArea.append(message + "\n");
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    /**
     * Получает файл от клиента.
     * @param in Входной поток данных от клиента.
     */
    private static void receiveFile(DataInputStream in) {
        try {
            String fileName = in.readUTF();
            log("Receiving file: " + fileName);
            logger.info("Receiving file: " + fileName);
            long fileSize = in.readLong();
            String encryptionAlgorithm = in.readUTF();

            // Determine key length
            int keyLength = encryptionAlgorithm.equals("AES") ? 16 : 8;
            byte[] secretKeyBytes = new byte[keyLength];
            in.readFully(secretKeyBytes);
            SecretKey secretKey = new SecretKeySpec(secretKeyBytes, encryptionAlgorithm);

            int publicKeyLength = in.readInt();
            byte[] publicKeyBytes = new byte[publicKeyLength];
            in.readFully(publicKeyBytes);
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            byte[] signature = new byte[SIGNATURE_LENGTH];
            in.readFully(signature);
            byte[] encryptedData = new byte[(int) fileSize];
            in.readFully(encryptedData);
            byte[] decryptedData = decryptData(encryptedData, secretKey, encryptionAlgorithm);

            // Use Stream API to write byte array to file
            try (FileOutputStream fos = new FileOutputStream("received_" + fileName)) {
                IntStream.range(0, decryptedData.length)
                        .forEach(i -> {
                            try {
                                fos.write(decryptedData[i]);
                            } catch (IOException e) {
                                log("Error while writing to file: " + e.getMessage());
                                logger.error("Error while writing to file: " + e.getMessage(), e);
                            }
                        });

                log("File saved: " + fileName);
                logger.info("File saved: " + fileName);
            }
        } catch (IOException e) {
            log("Error while receiving file: " + e.getMessage());
            logger.error("Error while receiving file: " + e.getMessage(), e);
        } catch (Exception e) {
            log("Error: " + e.getMessage());
            logger.error("Error: " + e.getMessage(), e);
        }
    }

    /**
     * Дешифрует данные.
     * @param data Зашифрованные данные.
     * @param secretKey Секретный ключ для дешифрования.
     * @param algorithm Алгоритм шифрования.
     * @return Расшифрованные данные.
     * @throws Exception Возможные ошибки при дешифровании.
     */
    private static byte[] decryptData(byte[] data, SecretKey secretKey, String algorithm) throws Exception {
        byte[] iv = new byte[algorithm.equals("DES") ? 8 : 16];
        System.arraycopy(data, 0, iv, 0, iv.length);
        byte[] encryptedData = new byte[data.length - iv.length];
        System.arraycopy(data, iv.length, encryptedData, 0, encryptedData.length);
        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(encryptedData);
    }
}
