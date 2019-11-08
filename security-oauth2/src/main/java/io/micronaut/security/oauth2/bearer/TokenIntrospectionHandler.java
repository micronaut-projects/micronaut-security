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

package io.micronaut.security.oauth2.bearer;

import io.micronaut.context.annotation.DefaultImplementation;

import java.util.Map;

/**
 * Handler responsible for processing token introspection metadata.
 * <p>
 * While token introspection endpoint and it's response are standardized in scope of
 * <a href="https://tools.ietf.org/html/rfc7662"> rfc7662 <a/> there are known <a href="https://stackoverflow.com/questions/12296017/how-to-validate-an-oauth-2-0-access-token-for-a-resource-server">custom solutions</a>
 * that does not conform the defined RFC or may be were introduced before RFC is published.
 * <p>
 * Developers can implement this interface if they need to support custom introspection response.
 *
 * @author svishnyakoff
 * @since 1.3.0
 */
@DefaultImplementation(DefaultTokenIntrospectionHandler.class)
public interface TokenIntrospectionHandler {

    /**
     * Takes introspection metadata as a map and produces introspection token
     *
     * @param tokenIntrospection introspection metadata
     * @return either valid or invalid introspection token.
     */
    IntrospectedToken handle(Map<String, Object> tokenIntrospection);
}
