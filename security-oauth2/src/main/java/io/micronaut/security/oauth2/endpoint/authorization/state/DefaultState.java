/*
 * Copyright 2017-2020 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.endpoint.authorization.state;

import io.micronaut.core.annotation.Introspected;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.util.UUID;

/**
 * Default state implementation.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Introspected
public class DefaultState implements MutableState {

    private URI originalUri;
    private URI redirectUri;
    private String nonce = UUID.randomUUID().toString();

    @Override
    @Nullable
    public URI getOriginalUri() {
        return originalUri;
    }

    @Nonnull
    @Override
    public String getNonce() {
        return nonce;
    }

    /**
     * @param originalUri The original URI
     */
    public void setOriginalUri(URI originalUri) {
        this.originalUri = originalUri;
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
        if (originalUri == null) {
            return 0;
        }
        return originalUri.hashCode();
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
