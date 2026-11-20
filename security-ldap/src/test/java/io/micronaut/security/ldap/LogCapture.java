package io.micronaut.security.ldap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Captures the events of a logger, at a given level, until it is closed.
 */
final class LogCapture implements AutoCloseable {

    private final Logger logger;
    private final Level originalLevel;
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    private LogCapture(String loggerName, Level level) {
        logger = (Logger) LoggerFactory.getLogger(loggerName);
        originalLevel = logger.getLevel();
        logger.setLevel(level);
        appender.start();
        logger.addAppender(appender);
    }

    /**
     * @param loggerName The name of the logger, which also captures its descendants
     * @param level      The level to enable while capturing
     * @return A capture that has started
     */
    static LogCapture start(String loggerName, Level level) {
        return new LogCapture(loggerName, level);
    }

    /**
     * @return The captured events
     */
    List<ILoggingEvent> events() {
        return appender.list;
    }

    /**
     * @return The formatted messages of the captured events
     */
    List<String> messages() {
        return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    @Override
    public void close() {
        logger.detachAppender(appender);
        logger.setLevel(originalLevel);
    }
}
