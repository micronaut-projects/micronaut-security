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
package io.micronaut.security.authentication;

import edu.umd.cs.findbugs.annotations.NonNull;
import io.micronaut.http.HttpHeaderValues;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

public class BasicAuthUtils {
    private static final Logger LOG = LoggerFactory.getLogger(BasicAuthUtils.class);
    private static final String PREFIX = HttpHeaderValues.AUTHORIZATION_PREFIX_BASIC + " ";

    /**
     *
     * @param authorization Authorization HTTP Header value
     * @return Extracted Credentials as a {@link UsernamePasswordCredentials} or an empty optional if not possible.
     */
    @NonNull
    public static Optional<UsernamePasswordCredentials> parseCredentials(@NonNull String authorization) {
        return Optional.of(authorization)
                .filter(s -> s.startsWith(PREFIX))
                .map(s -> s.substring(PREFIX.length()))
                .flatMap(BasicAuthUtils::decode);
    }

    private static Optional<UsernamePasswordCredentials> decode(String credentials) {
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(credentials);
        } catch (IllegalArgumentException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error while trying to Base 64 decode: {}", credentials);
            }
            return Optional.empty();
        }

        String token = new String(decoded, StandardCharsets.UTF_8);

        String[] parts = token.split(":");
        if (parts.length < 2) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Bad format of the basic auth header - Delimiter : not found");
            }
            return Optional.empty();
        }

        return Optional.of(new UsernamePasswordCredentials(parts[0], parts[1]));
    }
}
