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
package io.micronaut.security.endpoints;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Post;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.handlers.SignupHandler;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;

import java.util.Map;

/**
 * Handles signup requests by delegating to a {@link SignupHandler}.
 * @author Sergio del Amo
 * @since 5.6.0
 */
@Requires(property = SignupControllerConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Requires(classes = Controller.class)
@Requires(beans = { SignupHandler.class })
@Controller("${" + SignupControllerConfigurationProperties.PREFIX + ".path:/signup}")
@Secured(SecurityRule.IS_ANONYMOUS)
public class SignupController {

    private final SignupHandler<HttpRequest<?>, HttpResponse<?>> signupHandler;

    /**
     * @param signupHandler Collaborator which builds the HTTP response for a signup request.
     */
    public SignupController(SignupHandler<HttpRequest<?>, HttpResponse<?>> signupHandler) {
        this.signupHandler = signupHandler;
    }

    /**
     * @param request HTTP request
     * @param body Signup body
     * @return The HTTP response returned by the {@link SignupHandler}
     */
    @ExecuteOn(TaskExecutors.BLOCKING)
    @Post
    public HttpResponse<?> signup(HttpRequest<?> request, @Body Map<String, Object> body) {
        return signupHandler.signup(request, body);
    }
}
