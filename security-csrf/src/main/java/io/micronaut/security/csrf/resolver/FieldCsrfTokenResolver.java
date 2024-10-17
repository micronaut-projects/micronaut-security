/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.csrf.resolver;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.ServerHttpRequest;
import io.micronaut.http.body.ByteBody;
import io.micronaut.http.body.CloseableByteBody;
import io.micronaut.security.csrf.CsrfConfiguration;
import jakarta.inject.Singleton;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Resolves a CSRF token from a form-urlencoded body using the {@link ServerHttpRequest#byteBody()} API..
 *
 * @since 2.0.0
 */
@Requires(property = "micronaut.security.csrf.token-resolvers.field.enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Singleton
public class FieldCsrfTokenResolver implements CsrfTokenResolver<HttpRequest<?>> {
    private final CsrfConfiguration csrfConfiguration;

    public FieldCsrfTokenResolver(CsrfConfiguration csrfConfiguration) {
        this.csrfConfiguration = csrfConfiguration;
    }

    @Override
    public Optional<String> resolveToken(HttpRequest<?> request) {
        if (request instanceof ServerHttpRequest<?> serverHttpRequest) {
            return resolveToken(serverHttpRequest);
        }
        return Optional.empty();
    }

    private Optional<String> resolveToken(ServerHttpRequest<?> request) {
        try (CloseableByteBody ourCopy =
                     request.byteBody()
                             .split(ByteBody.SplitBackpressureMode.SLOWEST)
                             .allowDiscard()) {
            try (InputStream inputStream = ourCopy.toInputStream()) {
                String str = ofInputStream(inputStream);
                return extractCsrfTokenFromAFormUrlEncodedString(str);
            } catch (IOException e) {
                return Optional.empty();
            }
        }
    }

    private String ofInputStream(InputStream inputStream) throws IOException {
        final ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        for (int length; (length = inputStream.read(buffer)) != -1; ) {
            result.write(buffer, 0, length);
        }
        return result.toString(StandardCharsets.UTF_8);
    }

    private Optional<String> extractCsrfTokenFromAFormUrlEncodedString(String body) {
        final String[] arr = body.split("&");
        final String prefix = csrfConfiguration.getFieldName() + "=";
        for (String s : arr) {
            if (s.startsWith(prefix)) {
                return Optional.of(s.substring(prefix.length()));
            }
        }
        return Optional.empty();
    }
}
