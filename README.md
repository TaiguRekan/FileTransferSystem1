# FileTransferSystem1

**FileTransferSystem1** — это комплекс программ клиент-серверной архитектуры, позволяющий безопасно передавать файлы по сети в незащищенной среде. 

## StreamAPI

StreamAPI реализован в классе AESCipher.

## JavaDoc 

JavaDoc реализовал для методов.

## Gradle

Gradle реализован для создания пакета FileTransferSystem.

## Установка

Для корректного запуска приложения выполните следующие шаги:

1. **Запустите сервер:**
   - Откройте и запустите файл `FileTransferServer.java`. Это представление сервера, которое будет ожидать входящие соединения.

2. **Запустите клиент:**
   - После запуска сервера откройте и запустите файл `GUI.java`. Это графический интерфейс клиента, позволяющий пользователю выбирать файл для передачи и задавать параметры шифрования.

## Предупреждение

При первой настройке может возникнуть необходимость настройки правил в брандмауэре для разрешения входящих и исходящих подключений. Убедитесь, что порт, используемый сервером (по умолчанию `12345`), открыт для соединений.

## Используемые технологии

- **Java**: Основной язык программирования для реализации приложения.
- **AES и DES**: Алгоритмы симметричного шифрования для защиты файлов.
- **RSA**: Алгоритм для цифровой подписи и верификации.
- **Java Swing**: Для создания графического пользовательского интерфейса клиента.

## Компоненты

- `FileTransferServer.java`: Серверная часть c графическим интерфейсом, обеспечивающая прием и расшифровку файлов.
- `GUI.java`: Клиентская часть с графическим интерфейсом для передачи файлов.
- `AESCipher.java`, `DESCipher.java`: Классы для шифрования и дешифрования данных с использованием алгоритмов AES и DES.
- `BaseCipher.java`: Абстрактный класс, предоставляющий базовую функциональность для шифрования.
- `SignatureManager.java`, `SHA256Signature.java`, `SHA384Signature.java`: Классы для работы с цифровыми подписями.

## Как использовать

1. Запустите сервер и дождитесь загрузки.
2. Запустите клиент.
3. Введите IP-адрес сервера и путь к файлу, который хотите отправить.
4. Выберите алгоритм шифрования и алгоритм подписи.
5. Нажмите кнопку для отправки файла.


