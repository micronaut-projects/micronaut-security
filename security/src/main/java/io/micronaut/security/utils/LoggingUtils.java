/*
 * Copyright 2017-2022 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.utils;

import org.slf4j.Logger;

/**
 * Utility methods to avoid verbosity of logging statements. Mostly used to help reduce the Cognitive Complexity of
 * some methods.
 */
public final class LoggingUtils {

    private LoggingUtils() {
    }

    /**
     * Logs a message at the DEBUG level (only if it's enabled) according to the specified format and arguments.
     *
     * @param logger the SLF4J logger
     * @param message   the format string
     * @param args      a list of arguments
     */
    public static void debug(final Logger logger, final String message, final Object... args) {
        if (logger.isDebugEnabled()) {
            logger.debug(message, args);
        }
    }
}
