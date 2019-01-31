/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.endpoints;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpParameters;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Post;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.oauth2.handlers.AuthorizationResponseHandler;
import io.micronaut.security.oauth2.handlers.ErrorResponseHandler;
import io.micronaut.security.oauth2.openid.endpoints.authorization.AuthorizationRequestResponseTypeCodeCondition;
import io.micronaut.security.oauth2.openid.endpoints.token.TokenEndpointGrantTypeAuthorizationCodeCondition;
import io.micronaut.security.oauth2.responses.AuthenticationResponse;
import io.micronaut.security.oauth2.responses.AuthorizationResponseDetector;
import io.micronaut.security.oauth2.responses.AuthenticationResponseHttpParamsAdapter;
import io.micronaut.security.oauth2.responses.AuthenticationResponseMapAdapter;
import io.micronaut.security.oauth2.responses.ErrorResponse;
import io.micronaut.security.oauth2.responses.ErrorResponseDetector;
import io.micronaut.security.oauth2.responses.ErrorResponseHttpParamsAdapter;
import io.micronaut.security.oauth2.responses.ErrorResponseMapAdapter;
import io.micronaut.security.rules.SecurityRule;
import io.reactivex.Single;

import java.util.Map;

/**
 * Callback controller used for Authorization code flow.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Secured(SecurityRule.IS_ANONYMOUS)
@Requires(property = AuthorizationCodeControllerConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Requires(condition = AuthorizationRequestResponseTypeCodeCondition.class)
@Requires(condition = TokenEndpointGrantTypeAuthorizationCodeCondition.class)
@Requires(beans = {ErrorResponseHandler.class, AuthorizationResponseHandler.class})
@Controller("${" + AuthorizationCodeControllerConfigurationProperties.PREFIX + ".controller-path:/authcode}")
public class AuthorizationCodeController {

    private final ErrorResponseHandler errorResponseHandler;
    private final AuthorizationResponseHandler authorizationResponseHandler;

    /**
     *
     * @param errorResponseHandler Error Response Handler.
     * @param authorizationResponseHandler Authorization Response Handler.
     */
    public AuthorizationCodeController(ErrorResponseHandler errorResponseHandler,
                                       AuthorizationResponseHandler authorizationResponseHandler) {
        this.errorResponseHandler = errorResponseHandler;
        this.authorizationResponseHandler = authorizationResponseHandler;
    }

    /**
     * Callback action accessible through an Http Post request.
     *
     * @param formFields A Map encapsulating the form url encoded payload.
     * @param httpRequest The HTTP Request
     * @return An HttpResponse.
     */
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Post("${" + AuthorizationCodeControllerConfigurationProperties.PREFIX + ".action-path:/cb}")
    public Single<HttpResponse> cbPost(@Body Map formFields, HttpRequest httpRequest) {

        if (ErrorResponseDetector.isErrorResponse(formFields)) {
            ErrorResponse errorResponse = new ErrorResponseMapAdapter(formFields);
            return errorResponseHandler.handle(errorResponse);

        } else if (AuthorizationResponseDetector.isAuthorizationResponse(formFields)) {
            AuthenticationResponse authenticationResponse = new AuthenticationResponseMapAdapter(formFields);
            return authorizationResponseHandler.handle(httpRequest, authenticationResponse);
        }

        return Single.just(HttpResponse.ok());
    }

    /**
     * Callback action accessible through an Http Get request.
     *
     * @param parameters Http parameters
     * @param httpRequest The HTTP Request
     * @return An HttpResponse.
     */
    @Get("${" + AuthorizationCodeControllerConfigurationProperties.PREFIX + ".action-path:/cb}")
    public Single<HttpResponse> cbGet(HttpParameters parameters, HttpRequest httpRequest) {

        if (ErrorResponseDetector.isErrorResponse(parameters)) {
            ErrorResponse errorResponse = new ErrorResponseHttpParamsAdapter(parameters);
            return errorResponseHandler.handle(errorResponse);

        } else if (AuthorizationResponseDetector.isAuthorizationResponse(parameters)) {
            AuthenticationResponse authenticationResponse = new AuthenticationResponseHttpParamsAdapter(parameters);
            return authorizationResponseHandler.handle(httpRequest, authenticationResponse);
        }

        return Single.just(HttpResponse.ok());
    }

}
