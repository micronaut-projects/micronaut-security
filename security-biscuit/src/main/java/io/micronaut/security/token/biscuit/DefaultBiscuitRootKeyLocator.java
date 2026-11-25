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
package io.micronaut.security.token.biscuit;

import biscuit.format.schema.Schema;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import jakarta.inject.Singleton;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

import static io.micronaut.security.utils.LoggingUtils.debug;

/**
 * Configuration-backed {@link BiscuitRootKeyLocator}.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
@Requires(missingBeans = BiscuitRootKeyLocator.class)
@Singleton
public class DefaultBiscuitRootKeyLocator implements BiscuitRootKeyLocator {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultBiscuitRootKeyLocator.class);

    private final BiscuitConfiguration configuration;

    /**
     * @param configuration Biscuit configuration
     */
    public DefaultBiscuitRootKeyLocator(BiscuitConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public Optional<PublicKey> findRootKey(@Nullable Integer keyId) {
        String rootPublicKey = configuration.getRootPublicKey();
        if (StringUtils.isEmpty(rootPublicKey)) {
            return Optional.empty();
        }
        Integer configuredKeyId = configuration.getRootKeyId();
        if (configuredKeyId != null && keyId != null && !configuredKeyId.equals(keyId)) {
            return Optional.empty();
        }
        try {
            return Optional.of(new PublicKey(Schema.PublicKey.Algorithm.Ed25519, rootPublicKey));
        } catch (RuntimeException e) {
            debug(LOG, "Biscuit root public key parsing failed: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
    }
}
