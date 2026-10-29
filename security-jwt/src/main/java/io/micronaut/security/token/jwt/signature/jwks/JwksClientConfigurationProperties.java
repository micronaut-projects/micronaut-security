/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.token.jwt.signature.jwks;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.util.ArgumentUtils;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;
import io.micronaut.core.annotation.NonNull;

import java.time.Duration;

/**
 * {@link ConfigurationProperties} implementation of {@link JwksClientConfiguration}.
 *
 * @author Sergio del Amo
 * @since 3.11.3
 */
@ConfigurationProperties(JwksClientConfigurationProperties.PREFIX)
public class JwksClientConfigurationProperties implements JwksClientConfiguration {

    public static final String PREFIX = JwtConfigurationProperties.PREFIX + ".signatures.jwks-client";

    /**
     * The default failure back-off: 10 seconds.
     */
    @SuppressWarnings("WeakerAccess")
    public static final Duration DEFAULT_FAILURE_BACKOFF = Duration.ofSeconds(10);

    /**
     * The default retrieval timeout: 30 seconds.
     */
    @SuppressWarnings("WeakerAccess")
    public static final Duration DEFAULT_RETRIEVAL_TIMEOUT = Duration.ofSeconds(30);

    @NonNull
    private Duration failureBackoff = DEFAULT_FAILURE_BACKOFF;

    @NonNull
    private Duration retrievalTimeout = DEFAULT_RETRIEVAL_TIMEOUT;

    @Override
    @NonNull
    public Duration getFailureBackoff() {
        return failureBackoff;
    }

    @Override
    @NonNull
    public Duration getRetrievalTimeout() {
        return retrievalTimeout;
    }

    /**
     * How long a remote JWK Set retrieval may take before it is given up and treated as a failure, which starts the failure back-off.
     * It is applied as the connect timeout and the read timeout of the HTTP retrieval, so a JWKS endpoint which never answers does not block every token for that signature configuration.
     * Set it to 0 to disable the timeout. Default value (30 seconds).
     *
     * @param retrievalTimeout The retrieval timeout.
     */
    public void setRetrievalTimeout(@NonNull Duration retrievalTimeout) {
        ArgumentUtils.requireNonNull("retrievalTimeout", retrievalTimeout);
        this.retrievalTimeout = retrievalTimeout;
    }

    /**
     * How long a remote JWK Set is not requested again after a retrieval failed (for example, connection refused, non-2xx response or unparseable body) or returned no keys.
     * While the back-off lasts, tokens which cannot be verified with another signature configuration are rejected without contacting the JWKS endpoint again.
     * Set it to 0 to disable the back-off. Default value (10 seconds).
     *
     * @param failureBackoff The failure back-off duration.
     */
    public void setFailureBackoff(@NonNull Duration failureBackoff) {
        ArgumentUtils.requireNonNull("failureBackoff", failureBackoff);
        this.failureBackoff = failureBackoff;
    }
}
