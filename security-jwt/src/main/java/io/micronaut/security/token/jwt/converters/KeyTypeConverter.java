/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.token.jwt.converters;

import com.nimbusds.jose.jwk.KeyType;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.convert.ConversionContext;
import io.micronaut.core.convert.TypeConverter;
import jakarta.inject.Singleton;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Converts a string to a {@link KeyType}. The conversion is case-insensitive and only the key types defined by
 * RFC 7518 ({@code RSA}, {@code EC}, {@code OKP} and {@code oct}) are accepted; any other value (such as a typo) fails
 * with a {@link ConfigurationException} instead of silently producing a key type which matches no key or being ignored.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@Singleton
public class KeyTypeConverter implements TypeConverter<CharSequence, KeyType> {

    private static final List<KeyType> KNOWN = Arrays.asList(KeyType.RSA, KeyType.EC, KeyType.OKP, KeyType.OCT);

    /**
     *
     * @param object     e.g. EC
     * @param targetType The target type being converted to {@link com.nimbusds.jose.jwk.KeyType}
     * @param context    The {@link io.micronaut.core.convert.ConversionContext}
     * @return An optional {@link com.nimbusds.jose.jwk.KeyType}
     * @throws ConfigurationException if the value is not a known key type
     */
    @Override
    public Optional<KeyType> convert(CharSequence object, Class<KeyType> targetType, ConversionContext context) {
        if (object == null) {
            return Optional.empty();
        }
        String value = object.toString().trim();
        for (KeyType known : KNOWN) {
            if (known.getValue().equalsIgnoreCase(value)) {
                return Optional.of(known);
            }
        }
        throw new ConfigurationException("Unknown key type '" + value + "'. Supported values: RSA, EC, OKP, oct");
    }
}
