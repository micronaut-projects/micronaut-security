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
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.AuthenticationUserDetailsAdapter;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.filters.SecurityFilter;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.token.config.TokenConfiguration;
import io.micronaut.session.Session;
import io.micronaut.session.SessionStore;
import io.micronaut.session.http.SessionForRequest;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * A {@link LoginHandler} implementation for session based authentication.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
public class SessionLoginHandler implements LoginHandler {

    protected final String loginSuccess;
    protected final String loginFailure;
    protected final SessionStore<Session> sessionStore;
    private final String rolesKeyName;

    /**
     * Constructor.
     * @param securitySessionConfiguration Security Session Configuration
     * @param sessionStore The session store
     * @param tokenConfiguration Token Configuration
     * @deprecated Use {@link SessionLoginHandler(RedirectConfiguration, SessionStore, TokenConfiguration)} instead.
     */
    @Deprecated
    public SessionLoginHandler(SecuritySessionConfiguration securitySessionConfiguration,
                               SessionStore<Session> sessionStore,
                               TokenConfiguration tokenConfiguration) {
        this.loginFailure = securitySessionConfiguration.getLoginFailureTargetUrl();
        this.loginSuccess = securitySessionConfiguration.getLoginSuccessTargetUrl();
        this.sessionStore = sessionStore;
        this.rolesKeyName = tokenConfiguration.getRolesName();
    }

    /**
     * Constructor.
     * @param redirectConfiguration Redirect configuration
     * @param sessionStore The session store
     * @param tokenConfiguration Token Configuration
     */
    public SessionLoginHandler(RedirectConfiguration redirectConfiguration,
                               SessionStore<Session> sessionStore,
                               TokenConfiguration tokenConfiguration) {
        this.loginFailure = redirectConfiguration.getLoginFailure();
        this.loginSuccess = redirectConfiguration.getLoginSuccess();
        this.sessionStore = sessionStore;
        this.rolesKeyName = tokenConfiguration.getRolesName();
    }

    @Override
    public MutableHttpResponse<?> loginSuccess(UserDetails userDetails, HttpRequest<?> request) {
        Session session = SessionForRequest.find(request).orElseGet(() -> SessionForRequest.create(sessionStore, request));
        session.put(SecurityFilter.AUTHENTICATION, new AuthenticationUserDetailsAdapter(userDetails, rolesKeyName));
        try {
            URI location = new URI(loginSuccess);
            return HttpResponse.seeOther(location);
        } catch (URISyntaxException e) {
            return HttpResponse.serverError();
        }
    }

    @Override
    public MutableHttpResponse<?> loginFailed(AuthenticationResponse authenticationFailed) {
        try {
            URI location = new URI(loginFailure);
            return HttpResponse.seeOther(location);
        } catch (URISyntaxException e) {
            return HttpResponse.serverError();
        }
    }
}
