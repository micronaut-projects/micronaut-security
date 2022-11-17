/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.config;

import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.context.ServerContextPathProvider;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.util.List;

/**
 * Get redirection URLs combining context path and redirect configuration.
 * It prepends context path before redirect configuration URLs.
 * @since 3.7.2
 * @author Sergio del Amo
 */
@Singleton
public class DefaultRedirectService implements RedirectService {

    private final ServerContextPathProvider serverContextPathProvider;
    private final RedirectConfiguration redirectConfiguration;

    /**
     *
     * @param serverContextPathProviders Server Context Path providers
     * @param redirectConfiguration Redirect Configuration
     */
    @Inject
    public DefaultRedirectService(RedirectConfiguration redirectConfiguration,
                                  List<ServerContextPathProvider> serverContextPathProviders) {  // Inject list because when using Tomcat there is a multiple beans exception
        this(redirectConfiguration,
            serverContextPathProviders.isEmpty() ?
                null :
                serverContextPathProviders.get(0));
    }

    /**
     *
     * @param serverContextPathProvider Server Context Path provider
     * @param redirectConfiguration Redirect Configuration
     */
    public DefaultRedirectService(RedirectConfiguration redirectConfiguration,
                                  ServerContextPathProvider serverContextPathProvider) {
        if (serverContextPathProvider == null) {
            throw new ConfigurationException("no server context path providers available");
        }
        this.redirectConfiguration = redirectConfiguration;
        this.serverContextPathProvider = serverContextPathProvider;
    }

    @Override
    @NonNull
    public String loginSuccessUrl() {
        return ServerContextPathProviderUtils.prependContextPath(redirectConfiguration.getLoginSuccess(), serverContextPathProvider);
    }

    @Override
    @NonNull
    public String loginFailureUrl() {
        return ServerContextPathProviderUtils.prependContextPath(redirectConfiguration.getLoginFailure(), serverContextPathProvider);
    }

    @Override
    @NonNull
    public String logoutUrl() {
        return ServerContextPathProviderUtils.prependContextPath(redirectConfiguration.getLogout(), serverContextPathProvider);
    }

    @Override
    @NonNull
    public String unauthorizedUrl() {
        return ServerContextPathProviderUtils.prependContextPath(redirectConfiguration.getUnauthorized().getUrl(), serverContextPathProvider);
    }

    @Override
    @NonNull
    public String forbiddenUrl() {
        return ServerContextPathProviderUtils.prependContextPath(redirectConfiguration.getForbidden().getUrl(), serverContextPathProvider);
    }

    @Override
    @NonNull
    public String refreshUrl() {
        return ServerContextPathProviderUtils.prependContextPath(redirectConfiguration.getRefresh().getUrl(), serverContextPathProvider);
    }
}
