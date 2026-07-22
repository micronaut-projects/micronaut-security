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
package io.micronaut.security.scim.core;

import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.type.Argument;
import io.micronaut.serde.Decoder;
import io.micronaut.serde.Deserializer;
import jakarta.inject.Singleton;

import java.io.IOException;

/**
 * Deserializes RFC Boolean values and the case-insensitive string values emitted by some SCIM clients.
 *
 * @since 5.4.0
 */
@Singleton
@Internal
@Experimental
final class ScimBooleanDeserializer implements Deserializer<Boolean> {

    @Override
    public Boolean deserialize(
        Decoder decoder,
        DecoderContext context,
        Argument<? super Boolean> type
    ) throws IOException {
        Object value = decoder.decodeArbitrary();
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (value instanceof String stringValue) {
            if ("true".equalsIgnoreCase(stringValue)) {
                return true;
            }
            if ("false".equalsIgnoreCase(stringValue)) {
                return false;
            }
        }
        throw decoder.createDeserializationException("Expected a Boolean value", value);
    }
}
