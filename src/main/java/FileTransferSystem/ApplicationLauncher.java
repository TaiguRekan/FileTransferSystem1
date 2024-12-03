package FileTransferSystem;

import javax.swing.*;

public class ApplicationLauncher {
    public static void main(String[] args) {
        String[] options = {"Запустить сервер", "Запустить клиент", "Запустить клиент и сервис одновременно"};
        int choice = JOptionPane.showOptionDialog(null, "Выберите режим запуска:", "Файл передатчик",
                JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE,
                null, options, options[0]);

        switch (choice) {
            case 0: // Запустить только сервер
                new Thread(() -> {
                    FileTransferServer.main(args); // Запуск сервера
                }).start();
                break;
            case 1: // Запустить только клиент
                new Thread(() -> {
                    GUI.main(args); // Запуск клиента
                }).start();
                break;
            case 2: // Запустить оба
                new Thread(() -> {
                    FileTransferServer.main(args); // Запуск сервера
                }).start();
                new Thread(() -> {
                    GUI.main(args); // Запуск клиента
                }).start();
                break;
            default: // В случае отмены
                System.exit(0);
        }
    }
}
