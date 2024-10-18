/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.session.csrf;

import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.csrf.CsrfConfiguration;
import io.micronaut.security.csrf.generator.CsrfTokenGenerator;
import io.micronaut.security.errors.PriorToLoginPersistence;
import io.micronaut.security.session.SessionAuthenticationModeCondition;
import io.micronaut.security.session.SessionLoginHandler;
import io.micronaut.session.Session;
import io.micronaut.session.SessionStore;
import jakarta.inject.Singleton;

/**
 * Replacement of {@link SessionLoginHandler} that extends it and saves a CSRF token in the session.
 * @author Sergio del Amo
 * @since 4.11.0
 */
@Requires(condition = SessionAuthenticationModeCondition.class)
@Requires(beans = { CsrfConfiguration.class, CsrfTokenGenerator.class  })
@Replaces(SessionLoginHandler.class)
@Singleton
public class CsrfSessionLogingHandler extends SessionLoginHandler {

    private final CsrfConfiguration csrfConfiguration;
    private final CsrfTokenGenerator csrfTokenGenerator;

    /**
     * Constructor.
     *
     * @param redirectConfiguration   Redirect configuration
     * @param sessionStore            The session store
     * @param priorToLoginPersistence The persistence to store the original url
     * @param redirectService         Redirection Service
     * @param csrfConfiguration CSRF Configuration
     * @param csrfTokenGenerator CSRF Token Generator
     */
    public CsrfSessionLogingHandler(
            RedirectConfiguration redirectConfiguration,
            SessionStore<Session> sessionStore,
            @Nullable PriorToLoginPersistence<HttpRequest<?>,
                    MutableHttpResponse<?>> priorToLoginPersistence,
            RedirectService redirectService,
            CsrfConfiguration csrfConfiguration,
            CsrfTokenGenerator csrfTokenGenerator) {
        super(redirectConfiguration, sessionStore, priorToLoginPersistence, redirectService);
        this.csrfConfiguration = csrfConfiguration;
        this.csrfTokenGenerator = csrfTokenGenerator;
    }

    @Override
    protected Session saveAuthenticationInSession(Authentication authentication, HttpRequest<?> request) {
        Session session =  super.saveAuthenticationInSession(authentication, request);
        session.put(csrfConfiguration.getHttpSessionName(), csrfTokenGenerator.generate());
        return session;
    }
}
