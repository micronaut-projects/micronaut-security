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
package io.micronaut.security.endpoints;

import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.http.server.util.locale.HttpLocaleResolver;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.event.LogoutEvent;
import io.micronaut.security.handlers.LogoutHandler;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Inject;

import java.util.Locale;
import java.util.Optional;

/**
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(property = LogoutControllerConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Requires(classes = Controller.class)
@Requires(beans = { LogoutHandler.class, HttpHostResolver.class, HttpLocaleResolver.class })
@Controller("${" + LogoutControllerConfigurationProperties.PREFIX + ".path:/logout}")
@Secured(SecurityRule.IS_ANONYMOUS)
public class LogoutController {

    private final LogoutHandler<HttpRequest<?>, MutableHttpResponse<?>> logoutHandler;
    private final ApplicationEventPublisher<LogoutEvent> logoutEventPublisher;
    private final boolean getAllowed;
    private final HttpHostResolver httpHostResolver;
    private final HttpLocaleResolver httpLocaleResolver;
    private final LogoutControllerConfiguration logoutControllerConfiguration;

    /**
     * @param logoutHandler                 A collaborator which helps to build HTTP response if user logout.
     * @param logoutEventPublisher          The application event publisher
     * @param logoutControllerConfiguration Configuration for the Logout controller
     * @param httpHostResolver              The http host resolver
     * @param httpLocaleResolver            The http locale resolver
     * @since 4.11.0
     */
    @Inject
    public LogoutController(
        LogoutHandler<HttpRequest<?>, MutableHttpResponse<?>> logoutHandler,
        ApplicationEventPublisher<LogoutEvent> logoutEventPublisher,
        LogoutControllerConfiguration logoutControllerConfiguration,
        HttpHostResolver httpHostResolver,
        HttpLocaleResolver httpLocaleResolver) {
        this.logoutHandler = logoutHandler;
        this.logoutEventPublisher = logoutEventPublisher;
        this.getAllowed = logoutControllerConfiguration.isGetAllowed();
        this.httpHostResolver = httpHostResolver;
        this.httpLocaleResolver = httpLocaleResolver;
        this.logoutControllerConfiguration = logoutControllerConfiguration;
    }

    /**
     * @param logoutHandler                 A collaborator which helps to build HTTP response if user logout.
     * @param logoutEventPublisher          The application event publisher
     * @param logoutControllerConfiguration Configuration for the Logout controller
     * @param httpHostResolver              The http host resolver
     * @param httpLocaleResolver            The http locale resolver
     * @param logoutControllerConfigurationProperties  Configuration for the Logout Controller.
     * @since 4.7.0
     * @deprecated Use {@link #LogoutController(LogoutHandler, ApplicationEventPublisher, LogoutControllerConfiguration, HttpHostResolver, HttpLocaleResolver)} instead
     */
    @Deprecated(forRemoval = true, since = "4.11.0")
    public LogoutController(
            LogoutHandler<HttpRequest<?>, MutableHttpResponse<?>> logoutHandler,
            ApplicationEventPublisher<LogoutEvent> logoutEventPublisher,
            LogoutControllerConfiguration logoutControllerConfiguration,
            HttpHostResolver httpHostResolver,
            HttpLocaleResolver httpLocaleResolver,
            LogoutControllerConfigurationProperties logoutControllerConfigurationProperties) {
        this(logoutHandler, logoutEventPublisher, logoutControllerConfiguration, httpHostResolver, httpLocaleResolver);
    }

    /**
     * @param logoutHandler                 A collaborator which helps to build HTTP response if user logout.
     * @param logoutEventPublisher          The application event publisher
     * @param logoutControllerConfiguration Configuration for the Logout controller
     * @deprecated Use {@link #LogoutController(LogoutHandler, ApplicationEventPublisher, LogoutControllerConfiguration, HttpHostResolver, HttpLocaleResolver)} instead
     */
    @Deprecated(forRemoval = true, since = "4.7.0")
    public LogoutController(LogoutHandler<HttpRequest<?>, MutableHttpResponse<?>> logoutHandler,
                            ApplicationEventPublisher<LogoutEvent> logoutEventPublisher,
                            LogoutControllerConfiguration logoutControllerConfiguration) {
        this(
            logoutHandler,
            logoutEventPublisher,
            logoutControllerConfiguration,
            request -> null,
            new HttpLocaleResolver() {
                @Override
                public @NonNull Optional<Locale> resolve(@NonNull HttpRequest<?> context) {
                    return Optional.of(Locale.getDefault());
                }

                @Override
                public @NonNull Locale resolveOrDefault(@NonNull HttpRequest<?> context) {
                    return Locale.getDefault();
                }
            }
        );
    }

    /**
     * POST endpoint for Logout Controller.
     *
     * @param request        The {@link HttpRequest} being executed
     * @param authentication {@link Authentication} instance for current user
     * @return An AccessRefreshToken encapsulated in the HttpResponse or a failure indicated by the HTTP status
     */
    @Consumes({MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON})
    @Post
    public MutableHttpResponse<?> index(HttpRequest<?> request, @Nullable Authentication authentication) {
        Optional<MediaType> contentTypeOptional = request.getContentType();
        if (!(contentTypeOptional.isPresent() && logoutControllerConfiguration.getPostContentTypes().contains(contentTypeOptional.get().toString()))) {
            return HttpResponse.notFound();
        }
        return handleLogout(request, authentication);
    }

    /**
     * GET endpoint for Logout Controller.
     *
     * @param request        The {@link HttpRequest} being executed
     * @param authentication {@link Authentication} instance for current user
     * @return An AccessRefreshToken encapsulated in the HttpResponse or a failure indicated by the HTTP status
     */
    @Get
    public MutableHttpResponse<?> indexGet(HttpRequest<?> request, @Nullable Authentication authentication) {
        if (!getAllowed) {
            return HttpResponse.status(HttpStatus.METHOD_NOT_ALLOWED);
        }

        return handleLogout(request, authentication);
    }

    /**
     * @param request        The {@link HttpRequest} being executed
     * @param authentication {@link Authentication} instance for current user
     * @return An AccessRefreshToken encapsulated in the HttpResponse or a failure indicated by the HTTP status
     */
    protected MutableHttpResponse<?> handleLogout(HttpRequest<?> request, @Nullable Authentication authentication) {
        if (authentication != null) {
            logoutEventPublisher.publishEvent(
                new LogoutEvent(
                    authentication,
                    httpHostResolver.resolve(request),
                    httpLocaleResolver.resolveOrDefault(request)
                )
            );
        }
        return logoutHandler.logout(request);
    }
}
