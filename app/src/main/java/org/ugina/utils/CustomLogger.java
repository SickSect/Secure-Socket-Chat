package org.ugina.utils;

import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Slf4j
public class CustomLogger {
    // Шаблон даты: ГГГГ-ММ-ДД ЧЧ:ММ:СС.миллисекунды
    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    public static void logInfo(String msg, String className) {
        String timestamp = LocalDateTime.now().format(DATE_FORMATTER);
        String threadName = Thread.currentThread().getName();

        // %n или \n делает принудительный перенос строки.
        // Сообщение msg начнется с новой строки с небольшим отступом (табуляцией) для читаемости.
        log.info("\n\t[{}] [{}] [{}]\n\t-> {}",
                timestamp,
                threadName,
                className,
                msg);
    }
}
