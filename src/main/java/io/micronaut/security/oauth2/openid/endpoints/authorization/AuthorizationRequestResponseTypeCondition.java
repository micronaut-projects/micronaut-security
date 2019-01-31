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

package io.micronaut.security.oauth2.openid.endpoints.authorization;

import io.micronaut.context.BeanContext;
import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.context.exceptions.NoSuchBeanException;

/**
 * Conditions which verifies {@link AuthorizationEndpointRequestConfiguration#getResponseType()} is a particular response type.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public abstract class AuthorizationRequestResponseTypeCondition implements Condition {

     @Override
     public boolean matches(ConditionContext context) {
            BeanContext beanContext = context.getBeanContext();
            try {
                AuthorizationEndpointRequestConfiguration conf = beanContext.getBean(AuthorizationEndpointRequestConfiguration.class);
                if (conf.getResponseType().equals(checkedResponseType())) {
                    return true;
                }
            } catch (NoSuchBeanException e) {
                return false;
            }
            return false;
    }

    /**
     *
     * @return The Oauth 2.0 Grant type.
     */
    protected abstract String checkedResponseType();
}
