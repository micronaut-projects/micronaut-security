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

import dev.paseto.jpaseto.lang.Keys;
import io.micronaut.core.convert.ConversionContext;
import io.micronaut.core.convert.TypeConverter;
import jakarta.inject.Singleton;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Optional;

/**
 * Converts a {@link CharSequence} base64 encoded to a {@link javax.crypto.SecretKey}.
 *
 * @author Sergio del Amo
 * @since 3.2.0
 */
@Singleton
public class SecretKeyConverter implements TypeConverter<CharSequence, SecretKey> {

    @Override
    public Optional<SecretKey> convert(CharSequence object, Class<SecretKey> targetType, ConversionContext context) {
        if (object == null) {
            return Optional.empty();
        }
        String value = object.toString();
        byte[] decodedBytes = Base64.getDecoder().decode(value);
        return Optional.of(Keys.secretKey(decodedBytes));
    }
}
