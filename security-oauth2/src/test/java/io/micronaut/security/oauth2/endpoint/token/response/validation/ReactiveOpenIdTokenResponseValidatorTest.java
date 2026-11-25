/*
 * Copyright 2026 original authors
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
package io.micronaut.security.oauth2.endpoint.token.response.validation;

import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OauthClientConfigurationProperties;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * An implementation which does not override {@code validateWithoutNonce} keeps its previous behavior for flows without
 * an authorization request: it is asked to validate the token response with a {@code null} nonce.
 */
class ReactiveOpenIdTokenResponseValidatorTest {

    @Test
    void validateWithoutNonceDelegatesToValidateWithANullNonce() {
        RecordingValidator validator = new RecordingValidator();
        OauthClientConfiguration clientConfiguration = new OauthClientConfigurationProperties("auth");
        OpenIdProviderMetadata metadata = new DefaultOpenIdProviderMetadata("auth");
        OpenIdTokenResponse response = new OpenIdTokenResponse();

        String result = Mono.from(validator.validateWithoutNonce(clientConfiguration, metadata, response)).block();

        assertEquals("validated", result);
        assertEquals(1, validator.invocations.size());
        Invocation invocation = validator.invocations.getFirst();
        assertSame(clientConfiguration, invocation.clientConfiguration());
        assertSame(metadata, invocation.metadata());
        assertSame(response, invocation.response());
        assertNull(invocation.nonce());
    }

    private record Invocation(OauthClientConfiguration clientConfiguration,
                              OpenIdProviderMetadata metadata,
                              OpenIdTokenResponse response,
                              @Nullable String nonce) {
    }

    private static final class RecordingValidator implements ReactiveOpenIdTokenResponseValidator<String> {
        private final List<Invocation> invocations = new ArrayList<>();

        @Override
        public Publisher<String> validate(OauthClientConfiguration clientConfiguration,
                                          OpenIdProviderMetadata openIdProviderMetadata,
                                          OpenIdTokenResponse openIdTokenResponse,
                                          @Nullable String nonce) {
            invocations.add(new Invocation(clientConfiguration, openIdProviderMetadata, openIdTokenResponse, nonce));
            return Mono.just("validated");
        }
    }
}
