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
package io.micronaut.security.token.macaroons;

import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

final class MacaroonClaimsCodec {

    private static final String CLAIM_PREFIX = "micronaut:claim:";
    private static final String TYPE_STRING = "string";
    private static final String TYPE_BOOLEAN = "boolean";
    private static final String TYPE_LONG = "long";
    private static final String TYPE_DOUBLE = "double";
    private static final String TYPE_DATE = "date";
    private static final String TYPE_STRING_LIST = "string-list";
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private MacaroonClaimsCodec() {
    }

    static Optional<List<String>> encodeClaims(Map<String, Object> claims) {
        List<String> caveats = new ArrayList<>(claims.size());
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            Optional<String> caveat = encodeClaim(entry.getKey(), entry.getValue());
            if (caveat.isEmpty()) {
                return Optional.empty();
            }
            caveats.add(caveat.get());
        }
        return Optional.of(caveats);
    }

    static Optional<DecodedClaim> decodeClaim(String caveat) {
        if (!caveat.startsWith(CLAIM_PREFIX)) {
            return Optional.empty();
        }
        String[] parts = caveat.substring(CLAIM_PREFIX.length()).split(":", 3);
        if (parts.length != 3) {
            return Optional.empty();
        }
        try {
            String key = decodeString(parts[0]);
            Object value = switch (parts[1]) {
                case TYPE_STRING -> decodeString(parts[2]);
                case TYPE_BOOLEAN -> Boolean.valueOf(decodeString(parts[2]));
                case TYPE_LONG -> Long.valueOf(decodeString(parts[2]));
                case TYPE_DOUBLE -> Double.valueOf(decodeString(parts[2]));
                case TYPE_DATE -> Date.from(Instant.ofEpochMilli(Long.parseLong(decodeString(parts[2]))));
                case TYPE_STRING_LIST -> decodeStringList(parts[2]);
                default -> null;
            };
            return value == null ? Optional.empty() : Optional.of(new DecodedClaim(key, value));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private static Optional<String> encodeClaim(String key, @Nullable Object value) {
        if (value == null) {
            return Optional.empty();
        }
        Optional<EncodedValue> encodedValue = encodeValue(value);
        if (encodedValue.isEmpty()) {
            return Optional.empty();
        }
        EncodedValue encoded = encodedValue.get();
        return Optional.of(CLAIM_PREFIX + encodeString(key) + ':' + encoded.type() + ':' + encoded.value());
    }

    private static Optional<EncodedValue> encodeValue(Object value) {
        if (value instanceof CharSequence charSequence) {
            return Optional.of(new EncodedValue(TYPE_STRING, encodeString(charSequence.toString())));
        }
        if (value instanceof Boolean bool) {
            return Optional.of(new EncodedValue(TYPE_BOOLEAN, encodeString(bool.toString())));
        }
        if (value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long || value instanceof BigInteger) {
            return Optional.of(new EncodedValue(TYPE_LONG, encodeString(value.toString())));
        }
        if (value instanceof Float || value instanceof Double || value instanceof BigDecimal) {
            return Optional.of(new EncodedValue(TYPE_DOUBLE, encodeString(value.toString())));
        }
        if (value instanceof Date date) {
            return Optional.of(new EncodedValue(TYPE_DATE, encodeString(Long.toString(date.toInstant().toEpochMilli()))));
        }
        if (value instanceof Instant instant) {
            return Optional.of(new EncodedValue(TYPE_DATE, encodeString(Long.toString(instant.toEpochMilli()))));
        }
        if (value instanceof Collection<?> collection) {
            return encodeCollection(collection);
        }
        if (value instanceof String[] array) {
            return encodeCollection(List.of(array));
        }
        return Optional.empty();
    }

    private static Optional<EncodedValue> encodeCollection(Collection<?> collection) {
        List<String> values = new ArrayList<>(collection.size());
        for (Object item : collection) {
            if (!(item instanceof CharSequence charSequence) || charSequence.isEmpty()) {
                return Optional.empty();
            }
            values.add(encodeString(charSequence.toString()));
        }
        return Optional.of(new EncodedValue(TYPE_STRING_LIST, String.join(".", values)));
    }

    private static String encodeString(String value) {
        return ENCODER.encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String decodeString(String value) {
        return new String(DECODER.decode(value), StandardCharsets.UTF_8);
    }

    private static List<String> decodeStringList(String value) {
        if (value.isEmpty()) {
            return List.of();
        }
        String[] entries = value.split("\\.");
        List<String> decoded = new ArrayList<>(entries.length);
        for (String entry : entries) {
            decoded.add(decodeString(entry));
        }
        return decoded;
    }

    record DecodedClaim(String key, Object value) {
    }

    private record EncodedValue(String type, String value) {
    }
}
