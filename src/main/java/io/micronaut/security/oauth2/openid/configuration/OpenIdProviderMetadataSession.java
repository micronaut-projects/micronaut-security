/*
 * Copyright 2017-2018 original authors
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

package io.micronaut.security.oauth2.openid.configuration;

import javax.annotation.Nullable;

/**
 * @see <a href="https://openid.net/specs/openid-connect-session-1_0.html#OPMetadata">OpenID Connect Session Management</a>
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public interface OpenIdProviderMetadataSession {

    /**
     * check_session_iframe.
     * REQUIRED
     * @return URL of an OP iframe that supports cross-origin communications for session state information with the RP Client, using the HTML5 postMessage API.
     */
    @Nullable // although this is required, it will only be present if the JWKS endpoint supports the OpenID Connect Session Management Spec, thus Nullable
    String getCheckSessionIframe();

    /**
     * end_session_endpoint.
     * REQUIRED
     * @return URL at the OP to which an RP can perform a redirect to request that the End-User be logged out at the OP.
     */
    @Nullable // although this is required, it will only be present if the JWKS endpoint supports the OpenID Connect Session Management Spec, thus Nullable
    String getEndSessionEndpoint();
}
