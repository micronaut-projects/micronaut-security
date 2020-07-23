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

import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.functional.ThrowingSupplier;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.AuthenticationUserDetailsAdapter;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.errors.PriorToLoginPersistence;
import io.micronaut.security.filters.SecurityFilter;
import io.micronaut.security.handlers.RedirectingLoginHandler;
import io.micronaut.security.token.config.TokenConfiguration;
import io.micronaut.session.Session;
import io.micronaut.session.SessionStore;
import io.micronaut.session.http.SessionForRequest;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

/**
 * A {@link RedirectingLoginHandler} implementation for session based authentication.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(condition = SessionAuthenticationModeCondition.class)
@Singleton
public class SessionLoginHandler implements RedirectingLoginHandler {

    protected final String loginSuccess;
    protected final String loginFailure;
    protected final RedirectConfiguration redirectConfiguration;
    protected final SessionStore<Session> sessionStore;
    private final TokenConfiguration tokenConfiguration;
    private final PriorToLoginPersistence priorToLoginPersistence;

    /**
     * Constructor.
     * @param securitySessionConfiguration Security Session Configuration
     * @param sessionStore The session store
     * @param tokenConfiguration Token Configuration
     * @deprecated Use {@link SessionLoginHandler#SessionLoginHandler(RedirectConfiguration, SessionStore, TokenConfiguration, PriorToLoginPersistence)} instead.
     */
    @Deprecated
    public SessionLoginHandler(SecuritySessionConfiguration securitySessionConfiguration,
                               SessionStore<Session> sessionStore,
                               TokenConfiguration tokenConfiguration) {
        this(securitySessionConfiguration.toRedirectConfiguration(),
                sessionStore,
                tokenConfiguration,
                null);
    }

    /**
     * Constructor.
     * @param redirectConfiguration Redirect configuration
     * @param sessionStore The session store
     * @param tokenConfiguration Token Configuration
     * @param priorToLoginPersistence The persistence to store the original url
     */
    @Inject
    public SessionLoginHandler(RedirectConfiguration redirectConfiguration,
                               SessionStore<Session> sessionStore,
                               TokenConfiguration tokenConfiguration,
                               @Nullable PriorToLoginPersistence priorToLoginPersistence) {
        this.loginFailure = redirectConfiguration.getLoginFailure();
        this.loginSuccess = redirectConfiguration.getLoginSuccess();
        this.redirectConfiguration = redirectConfiguration;
        this.sessionStore = sessionStore;
        this.tokenConfiguration = tokenConfiguration;
        this.priorToLoginPersistence = priorToLoginPersistence;
    }

    @Override
    public MutableHttpResponse<?> loginSuccess(UserDetails userDetails, HttpRequest<?> request) {
        Session session = SessionForRequest.find(request).orElseGet(() -> SessionForRequest.create(sessionStore, request));
        session.put(SecurityFilter.AUTHENTICATION, new AuthenticationUserDetailsAdapter(userDetails, tokenConfiguration.getRolesName(), tokenConfiguration.getNameKey()));
        try {
            MutableHttpResponse<?> response = HttpResponse.status(HttpStatus.SEE_OTHER);
            ThrowingSupplier<URI, URISyntaxException> uriSupplier = () -> new URI(loginSuccess);
            if (priorToLoginPersistence != null) {
                Optional<URI> originalUri = priorToLoginPersistence.getOriginalUri(request, response);
                if (originalUri.isPresent()) {
                    uriSupplier = originalUri::get;
                }
            }
            response.getHeaders().location(uriSupplier.get());
            return response;
        } catch (URISyntaxException e) {
            return HttpResponse.serverError();
        }
    }

    @Override
    public MutableHttpResponse<?> loginRefresh(UserDetails userDetails, String refreshToken, HttpRequest<?> request) {
        throw new UnsupportedOperationException("Session based logins do not support refresh");
    }

    @Override
    public MutableHttpResponse<?> loginFailed(AuthenticationResponse authenticationFailed, HttpRequest<?> request) {
        try {
            URI location = new URI(loginFailure);
            return HttpResponse.seeOther(location);
        } catch (URISyntaxException e) {
            return HttpResponse.serverError();
        }
    }
}
