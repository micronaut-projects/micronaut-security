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

package io.micronaut.security.oauth2.openid.endpoints;

import javax.annotation.Nullable;

/**
 * Default implementation of {@link OpenIdEndpoints}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class DefaultOpenIdEndpoints implements OpenIdEndpoints {

    private String authorization;
    private String endSession;
    private String introspection;
    private String registration;
    private String revocation;
    private String token;
    private String userinfo;

    /**
     *
     * @param authorization Authorization endpoint url
     * @param endSession End-session endpoint url
     * @param introspection Instrospection endpoint url
     * @param registration Registration endpoint url
     * @param revocation Revocation endpoint url
     * @param token Token endpoint url
     * @param userinfo User info endpoint url
     */
    public DefaultOpenIdEndpoints(String authorization,
            String endSession,
            String introspection,
            String registration,
            String revocation,
            String token,
            String userinfo) {
        this.authorization = authorization;
        this.endSession = endSession;
        this.introspection = introspection;
        this.registration = registration;
        this.revocation = revocation;
        this.token = token;
        this.userinfo = userinfo;
    }

    @Override
    public String getAuthorization() {
        return authorization;
    }

    @Override
    @Nullable
    public String getEndSession() {
        return endSession;
    }

    @Override
    public String getIntrospection() {
        return introspection;
    }

    @Override
    public String getRegistration() {
        return registration;
    }

    @Override
    public String getRevocation() {
        return revocation;
    }

    @Override
    public String getToken() {
        return token;
    }

    @Override
    public String getUserinfo() {
        return userinfo;
    }
}
