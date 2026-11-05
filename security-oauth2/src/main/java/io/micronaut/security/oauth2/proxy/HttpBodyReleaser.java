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
package io.micronaut.security.oauth2.proxy;

import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpResponse;

/**
 * Releases the body of an HTTP response which will not be consumed.
 * <p>
 * {@link WellKnownProxyFilter} uses it when it rejects an authorization server response instead of relaying it.
 * Server-side HTTP implementations may hold on to the response body, for example as reference-counted buffers
 * or an unread stream, until it is consumed or released. Dropping such a response without releasing it leaks
 * memory and can keep the connection to the authorization server open.
 * <p>
 * The implementation depends on the HTTP runtime, so the filter looks up an optional bean of this type
 * and does nothing when none is available, for example when Netty is absent.
 */
@Internal
public interface HttpBodyReleaser {

    /**
     * Releases the body of the given response. The response must not be read, relayed or released again afterwards.
     * <p>
     * Implementations ignore responses they do not know how to release and must not throw.
     *
     * @param response The response whose body is discarded
     */
    void release(HttpResponse<?> response);
}
