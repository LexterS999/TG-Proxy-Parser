# Telegram Channel Profile Parser and Extractor

Этот Python скрипт предназначен для автоматического сбора конфигурационных профилей (vless, hy2, tuic, trojan) из телеграм-каналов. Скрипт использует многопоточность для ускорения процесса парсинга, оценивает найденные профили на основе заданных критериев, фильтрует дубликаты и подстроки, и сохраняет лучшие профили в файл `config-tg.txt`.

Особенностью скрипта является автоматическое удаление телеграм-каналов из списка для парсинга, если в них не удается найти профили после нескольких последовательных проверок. Это позволяет поддерживать список каналов в актуальном состоянии, исключая неинформативные источники.

## Основные Возможности

*   **Многопоточный парсинг:** Ускорение сбора данных за счет одновременной обработки нескольких телеграм-каналов.
*   **Оценка профилей:**  Каждый найденный профиль оценивается на основе набора параметров, что позволяет отбирать наиболее качественные конфигурации.
*   **Фильтрация и очистка профилей:** Удаление дубликатов, подстрок, и очистка от лишних символов для получения чистого списка уникальных профилей.
*   **Автоматическое удаление каналов:** Каналы, в которых не обнаружены профили после `MAX_FAILED_CHECKS` (по умолчанию 4) последовательных проверок, автоматически исключаются из дальнейшего парсинга.
*   **Логирование:** Подробное логирование процесса работы скрипта, включая ошибки, статистику парсинга и информацию об удалении каналов.
*   **Конфигурация через файлы:** Список телеграм-каналов для парсинга, история неудачных проверок и выходные профили хранятся в отдельных файлах.
*   **Период скачивания:** Скрипт настроен на работу в определенный период месяца (дни начала и окончания задаются константами), что позволяет контролировать частоту сбора профилей.

## Конфигурация

Для работы скрипта необходимо настроить следующие файлы и константы:

### Файлы:

*   **`telegram_channels.json`:**  Файл в формате JSON, содержащий список имен телеграм-каналов для парсинга. Пример содержимого:
    ```json
    [
      "channel_name_1",
      "channel_name_2",
      "another_channel"
    ]
    ```
*   **`config-tg.txt`:** Файл, в который будут сохранены отфильтрованные и отсортированные конфигурационные профили. Создается автоматически при первом запуске скрипта, если не существует.
*   **`channel_failure_history.json`:** Файл для хранения истории неудачных проверок телеграм-каналов. Используется для реализации автоматического удаления каналов. Создается и управляется скриптом автоматически.

### Константы в коде:

Основные константы, которые можно настроить в начале скрипта:

*   `MAX_THREADS_PARSING`:  Максимальное количество потоков для парсинга (по умолчанию 50).
*   `REQUEST_TIMEOUT`:  Время ожидания ответа от сервера при запросе к Telegram (в секундах, по умолчанию 10).
*   `MIN_PROFILES_TO_DOWNLOAD`: Минимальное количество профилей для сохранения в `config-tg.txt`, даже если найдено меньше (по умолчанию 20).
*   `MAX_PROFILES_TO_DOWNLOAD`: Максимальное количество профилей для сохранения в `config-tg.txt` (по умолчанию 4000).
*   `ALLOWED_PROTOCOLS`:  Набор поддерживаемых протоколов (`vless`, `hy2`, `tuic`, `trojan`).
*   `PROFILE_SCORE_WEIGHTS`: Веса параметров профиля, используемые для расчета скора. Можно настроить, чтобы придать большую важность определенным параметрам.
*   `MAX_FAILED_CHECKS`: Максимальное количество последовательных неудачных проверок канала перед его удалением из списка (по умолчанию 4).
*   `START_DAY_PROFILE_DOWNLOAD` и `END_DAY_PROFILE_DOWNLOAD`:  Дни месяца начала и окончания периода работы скрипта (по умолчанию с 1 по 14 число каждого месяца).

## Использование

### Предварительные требования:

*   Python 3.x
*   Установленные библиотеки Python: `requests`, `bs4` (BeautifulSoup4), `urllib3`.

    Установить библиотеки можно с помощью pip:
    ```bash
    pip install requests beautifulsoup4 urllib3
    ```

### Запуск скрипта:

1.  Убедитесь, что файлы `telegram_channels.json` и скрипт Python находятся в одной директории.
2.  Настройте файл `telegram_channels.json`, добавив в него имена интересующих вас телеграм-каналов.
3.  При необходимости, настройте константы в начале Python скрипта.
4.  Запустите скрипт из командной строки:
    ```bash
    python tg-parser.py
    ```
    *(Замените `tg-parser.py` на фактическое имя файла вашего скрипта)*

### Результат:

После завершения работы скрипта, отфильтрованные и отсортированные профили будут сохранены в файле `config-tg.txt`. В консоль будет выведена итоговая статистика работы скрипта, включая время выполнения, количество обработанных каналов, найденных профилей и удаленных каналов.

## Лицензия

[MIT License](https://rem.mit-license.org/)
