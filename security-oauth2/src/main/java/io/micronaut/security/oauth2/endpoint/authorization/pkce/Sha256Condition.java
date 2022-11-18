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
package io.micronaut.security.oauth2.endpoint.authorization.pkce;

import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * {@link Condition} which evaluates to {@literal true} if SHA-256 algorithm is supported.
 * @author Sergio del Amo
 * @since 3.9.0
 */
public class Sha256Condition implements Condition {
    @Override
    public boolean matches(ConditionContext context) {
        try {
            MessageDigest sha256Digester = MessageDigest.getInstance("SHA-256");
            return true;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }
}
