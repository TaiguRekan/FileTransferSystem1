package FileTransferSystem;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class FileTransferServer {
    private static final int SIGNATURE_LENGTH = 256; // Длина подписи для RSA 2048 бит
    private static volatile boolean running = false; // Флаг для управления состоянием сервера
    private static JTextArea logArea; // Область для логов

    public static void main(String[] args) {
        SwingUtilities.invokeLater(FileTransferServer::createAndShowGUI);
    }

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("Файл передатчик Сервер");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);
        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);
        frame.add(scrollPane, BorderLayout.CENTER);
        JPanel buttonPanel = new JPanel();

        JButton startButton = new JButton("Запустить сервер");
        JButton stopButton = new JButton("Остановить сервер");
        stopButton.setEnabled(false); // Деактивируем кнопку остановки

        startButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                startServer();
                startButton.setEnabled(false);
                stopButton.setEnabled(true);
            }
        });

        stopButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                stopServer();
                startButton.setEnabled(true);
                stopButton.setEnabled(false);
            }
        });

        buttonPanel.add(startButton);
        buttonPanel.add(stopButton);
        frame.add(buttonPanel, BorderLayout.SOUTH);
        frame.setVisible(true);
    }

    private static void startServer() {
        running = true;
        new Thread(() -> {
            int port = 12345;
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                log("Сервер запущен и ожидает подключения...");
                while (running) {
                    try (Socket socket = serverSocket.accept();
                         DataInputStream in = new DataInputStream(socket.getInputStream())) {
                        log("Клиент подключен: " + socket.getInetAddress().getHostAddress());
                        receiveFile(in);
                    } catch (IOException e) {
                        if (running) {
                            log("Ошибка: " + e.getMessage());
                        }
                    }
                }
            } catch (IOException e) {
                log("Ошибка при запуске сервера: " + e.getMessage());
            }
        }).start();
    }

    private static void stopServer() {
        running = false; // Устанавливаем флаг для остановки сервера
        log("Сервер остановлен.");
    }

    private static void log(String message) {
        logArea.append(message + "\n");
        logArea.setCaretPosition(logArea.getDocument().getLength()); // Прокрутка вниз
    }

    private static void receiveFile(DataInputStream in) {
        try {
            // Получаем имя файла
            String fileName = in.readUTF();
            log("Получение файла: " + fileName);
            // Получаем размер файла
            long fileSize = in.readLong();
            // Получаем алгоритм шифрования
            String encryptionAlgorithm = in.readUTF();
            // Получаем симметричный ключ
            int keyLength = "AES".equals(encryptionAlgorithm) ? 16 : 8;
            byte[] secretKeyBytes = new byte[keyLength];
            in.readFully(secretKeyBytes);
            SecretKey secretKey = new SecretKeySpec(secretKeyBytes, encryptionAlgorithm);

            // Читаем длину открытого ключа клиента
            int publicKeyLength = in.readInt();
            byte[] publicKeyBytes = new byte[publicKeyLength];
            in.readFully(publicKeyBytes);
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            // Получаем подпись
            byte[] signature = new byte[SIGNATURE_LENGTH];
            in.readFully(signature);

            // Получаем зашифрованные данные
            byte[] encryptedData = new byte[(int) fileSize];
            in.readFully(encryptedData);

            // Расшифровка файла
            byte[] decryptedData = decryptData(encryptedData, secretKey, encryptionAlgorithm);

            // Сохранение расшифрованного файла
            try (FileOutputStream fos = new FileOutputStream("received_" + fileName)) {
                fos.write(decryptedData);
                log("Файл сохранен: " + fileName);
            }
        } catch (IOException e) {
            log("Ошибка при получении файла: " + e.getMessage());
        } catch (Exception e) {
            log("Ошибка: " + e.getMessage());
        }
    }

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
