# FileTransferSystem
**Программа реализована на английском языке, но передача файлов будет корректно работать и на русском

**FileTransferSystem1** — это комплекс программ клиент-серверной архитектуры, позволяющий безопасно передавать файлы по сети в незащищенной среде. 

## StreamAPI

StreamAPI реализован в FileTransferServer посредством IntStream для обработки массивов байтов, если в будущем будет реализовано сохранение полученных данных как коллекции.

## JavaDoc 

JavaDoc реализован для методов.

## Gradle

Gradle реализован для создания пакета FileTransferSystem.

## Переиспользование кода

Переиспользование кода реализовано с помощью интерфейсов и наследования, например, класс DESCipher - конкретная реализация шифра DES, наследует класс BaseCipher - класс, абстрактно описывающий шифры.

## log4j

Реализовано логгирование посредством добавления зависимостей log4j2 в Gradlem, производится в консоль и файл.

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
- `BaseSignature.java`: Абстрактный класс, предоставляющий базовую функциональность для подписи.
- `SignatureManager.java`, `SHA256Signature.java`, `SHA384Signature.java`: Классы для работы с цифровыми подписями.

## Как использовать

1. Откройте FileTransferSystem-1.0SNAPSHOT.jar через консоль
2. Запустите сервер и дождитесь загрузки.
3. Запустите клиент.
4. Введите IP-адрес сервера и путь к файлу, который хотите отправить.
5. Выберите алгоритм шифрования и алгоритм подписи.
6. Нажмите кнопку для отправки файла.
7. Рекомендуемые настройки для безопасной передачи: AES, SHA384.

