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

import io.micronaut.core.convert.value.MutableConvertibleValues;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.filters.SecurityFilter;
import io.micronaut.security.handlers.LogoutHandler;
import io.micronaut.session.Session;
import io.micronaut.session.http.HttpSessionFilter;

import javax.inject.Inject;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

/**
 * {@link LogoutHandler} implementation for Session-Based Authentication.
 * @author Sergio del Amo
 * @since 1.0
 */
public class SessionLogoutHandler implements LogoutHandler {

    protected final String logout;

    /**
     * Constructor.
     *
     * @param securitySessionConfiguration Security Session Configuration session store
     * @deprecated Use {@link SessionLogoutHandler(RedirectConfiguration)} instead.
     */
    @Deprecated
    public SessionLogoutHandler(SecuritySessionConfiguration securitySessionConfiguration) {
        this.logout = securitySessionConfiguration.getLogoutTargetUrl();
    }

    /**
     * Constructor.
     * @param redirectConfiguration Redirect Configuration
     */
    @Inject
    public SessionLogoutHandler(RedirectConfiguration redirectConfiguration) {
        this.logout = redirectConfiguration.getLogout();
    }

    @Override
    public MutableHttpResponse<?> logout(HttpRequest<?> request) {
        MutableConvertibleValues<Object> attrs = request.getAttributes();
        Optional<Session> existing = attrs.get(HttpSessionFilter.SESSION_ATTRIBUTE, Session.class);
        if (existing.isPresent()) {
            Session session = existing.get();
            session.remove(SecurityFilter.AUTHENTICATION);
        }
        try {
            URI location = new URI(logout);
            return HttpResponse.seeOther(location);
        } catch (URISyntaxException e) {
            return HttpResponse.serverError();
        }
    }
}
