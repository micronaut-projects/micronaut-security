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
package io.micronaut.security.oauth2.endpoint.endsession.request;

/**
 * Industry Authorization servers.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public enum AuthorizationServer {

    OKTA("okta"),
    COGNITO("cognito"),
    AUTH0("auth0");

    private String name;

    /**
     * Authorization Server constructor.
     * @param name the authorization server name.
     */
    AuthorizationServer(String name) {
        this.name = name;
    }

    /**
     *
     * @return the authorization server name.
     */
    public String getName() {
        return this.name;
    }

    @Override
    public String toString() {
        return getName();
    }
}

