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
package io.micronaut.security.session;

import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.AuthenticationFetcher;
import io.micronaut.security.filters.SecurityFilter;
import io.micronaut.security.token.TokenAuthenticationFetcher;
import io.micronaut.session.Session;
import io.micronaut.session.http.HttpSessionFilter;
import io.reactivex.Maybe;
import org.reactivestreams.Publisher;

import jakarta.inject.Singleton;
import java.util.Optional;

/**
 * Attempts to retrieve an instance of {@link Authentication} from {@link Session}.
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 */
@Singleton
public class SessionAuthenticationFetcher implements AuthenticationFetcher {

    /**
     * The order of the fetcher.
     */
    public static final Integer ORDER = TokenAuthenticationFetcher.ORDER - 100;

    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
        return Maybe.<Authentication>create(emitter -> {
            Optional<Session> opt = request.getAttributes().get(HttpSessionFilter.SESSION_ATTRIBUTE, Session.class);
            if (opt.isPresent()) {
                Session session = opt.get();
                Optional<Authentication> authentication = session.get(SecurityFilter.AUTHENTICATION, Authentication.class);
                authentication.ifPresent(emitter::onSuccess);
            }
            emitter.onComplete();
        }).toFlowable();
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
