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

package io.micronaut.security.oauth2.openid.providers;

import io.micronaut.context.BeanContext;
import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.value.PropertyResolver;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import io.micronaut.security.oauth2.openid.configuration.OpenIdProviderConfigurationProperties;

import java.util.Optional;

/**
 * Abstract Condition to check if micronaut.security.oauth2.openid.issuer contains a search sequence.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public abstract class OpenidConfigurationCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context) {
        BeanContext beanContext = context.getBeanContext();
        if (beanContext instanceof PropertyResolver) {
            PropertyResolver propertyResolver = (PropertyResolver) beanContext;
            Optional<String> openIdConfigurationUrl = propertyResolver.get(OpenIdProviderConfigurationProperties.PREFIX + ".issuer", String.class);
            return openIdConfigurationUrl.map(s -> s.contains(getSearchSequence())).orElse(false);
        }
        return false;
    }

    /**
     *
     * @return the Search sequence which will be checked against the value of property micronaut.security.oauth2.openid.issuer.
     */
    protected abstract String getSearchSequence();
}
