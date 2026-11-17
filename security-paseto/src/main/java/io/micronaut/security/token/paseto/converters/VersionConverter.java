/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.token.paseto.converters;

import dev.paseto.jpaseto.Version;
import dev.paseto.jpaseto.UnsupportedPasetoException;
import io.micronaut.core.convert.ConversionContext;
import io.micronaut.core.convert.TypeConverter;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Optional;

/**
 * Converts a {@link CharSequence} to a {@link Version}.
 *
 * @author Sergio del Amo
 * @since 3.2.0
 */
@Singleton
public class VersionConverter implements TypeConverter<CharSequence, Version> {

    private static final Logger LOG = LoggerFactory.getLogger(VersionConverter.class);

    @Override
    public Optional<Version> convert(CharSequence object, Class<Version> targetType, ConversionContext context) {
        if (object == null) {
            return Optional.empty();
        }
        String value = object.toString();
        try {
            return Optional.of(Version.from(value));
        } catch (UnsupportedPasetoException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("could not parse version", e);
            }
        }
        return Optional.empty();
    }
}
