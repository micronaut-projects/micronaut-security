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
package io.micronaut.security.oauth2.endpoint.authorization.state;

import io.micronaut.core.annotation.Introspected;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.annotation.ReflectiveAccess;
import java.net.URI;
import java.util.Objects;
import java.util.UUID;

/**
 * Default state implementation.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@ReflectiveAccess
@Introspected
public class DefaultState implements MutableState {

    private URI redirectUri;
    private String nonce = UUID.randomUUID().toString();

    @NonNull
    @Override
    public String getNonce() {
        return nonce;
    }

    /**
     * This method is a no-op. The value is ignored and never serialized into the state. Redirecting back to the
     * original URI after login is handled by {@link io.micronaut.security.errors.PriorToLoginPersistence}.
     *
     * @param originalUri The original URI, ignored
     * @deprecated The original URI is not part of the state. Use {@link io.micronaut.security.errors.PriorToLoginPersistence} instead.
     */
    @Deprecated(since = "5.4.0", forRemoval = true)
    @Override
    public void setOriginalUri(URI originalUri) {
        // no-op
    }

    /**
     * @param nonce The nonce
     */
    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    @Nullable
    @Override
    public URI getRedirectUri() {
        return redirectUri;
    }

    /**
     * @param redirectUri the URI to redirect to
     */
    public void setRedirectUri(URI redirectUri) {
        this.redirectUri = redirectUri;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(nonce);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof State)) {
            return false;
        }
        State other = (State) obj;

        return nonce.equals(other.getNonce());
    }
}
