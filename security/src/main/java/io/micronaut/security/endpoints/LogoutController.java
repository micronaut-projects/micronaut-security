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
package io.micronaut.security.endpoints;

import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventPublisher;
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
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.event.LogoutEvent;
import io.micronaut.security.handlers.LogoutHandler;
import io.micronaut.security.rules.SecurityRule;

import javax.inject.Inject;

/**
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(property = LogoutControllerConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Requires(beans = LogoutHandler.class)
@Controller("${" + LogoutControllerConfigurationProperties.PREFIX + ".path:/logout}")
@Secured(SecurityRule.IS_ANONYMOUS)
public class LogoutController {

    private final LogoutHandler logoutHandler;
    private final ApplicationEventPublisher eventPublisher;
    private final boolean getAllowed;

    /**
     *
     * @param logoutHandler A collaborator which helps to build HTTP response if user logout.
     * @param eventPublisher The application event publisher
     * @param logoutControllerConfiguration Configuration for the Logout controller
     */
    @Inject
    public LogoutController(LogoutHandler logoutHandler,
                            ApplicationEventPublisher eventPublisher,
                            LogoutControllerConfiguration logoutControllerConfiguration) {
        this.logoutHandler = logoutHandler;
        this.eventPublisher = eventPublisher;
        this.getAllowed = logoutControllerConfiguration.isGetAllowed();
    }

    /**
     * POST endpoint for Logout Controller.
     *
     * @param request The {@link HttpRequest} being executed
     * @param authentication {@link Authentication} instance for current user
     * @return An AccessRefreshToken encapsulated in the HttpResponse or a failure indicated by the HTTP status
     */
    @Consumes({MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON})
    @Post
    public MutableHttpResponse<?> index(HttpRequest<?> request, @Nullable Authentication authentication) {
        return handleLogout(request, authentication);
    }

    /**
     * GET endpoint for Logout Controller.
     *
     * @param request The {@link HttpRequest} being executed
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
     *
     * @param request The {@link HttpRequest} being executed
     * @param authentication {@link Authentication} instance for current user
     * @return An AccessRefreshToken encapsulated in the HttpResponse or a failure indicated by the HTTP status
     */
    protected MutableHttpResponse<?> handleLogout(HttpRequest<?> request, @Nullable Authentication authentication) {
        if (authentication != null) {
            eventPublisher.publishEvent(new LogoutEvent(authentication));
        }
        return logoutHandler.logout(request);
    }
}
