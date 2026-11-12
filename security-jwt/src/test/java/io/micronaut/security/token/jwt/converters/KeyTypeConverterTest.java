/*
 * Copyright 2017-2026 original authors
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
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyTypeConverterTest {

    private final KeyTypeConverter converter = new KeyTypeConverter();

    @Test
    void convertsKnownKeyTypesCaseInsensitively() {
        assertEquals(Optional.of(KeyType.RSA), convert("RSA"));
        assertEquals(Optional.of(KeyType.RSA), convert("rsa"));
        assertEquals(Optional.of(KeyType.EC), convert("Ec"));
        assertEquals(Optional.of(KeyType.OKP), convert("okp"));
        assertEquals(Optional.of(KeyType.OCT), convert("OCT"));
    }

    @Test
    void rejectsUnknownKeyTypes() {
        assertThrows(ConfigurationException.class, () -> convert("RSAA"));
        assertThrows(ConfigurationException.class, () -> convert(""));
        assertThrows(ConfigurationException.class, () -> convert("elliptic"));
    }

    private Optional<KeyType> convert(String value) {
        return converter.convert(value, KeyType.class, ConversionContext.DEFAULT);
    }
}
