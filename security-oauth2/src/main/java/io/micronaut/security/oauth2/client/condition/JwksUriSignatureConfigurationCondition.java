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
package io.micronaut.security.oauth2.client.condition;

import io.micronaut.context.condition.Condition;
import io.micronaut.context.condition.ConditionContext;
import io.micronaut.core.annotation.AnnotationMetadataProvider;
import io.micronaut.core.annotation.Internal;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfigurationProperties;
import io.micronaut.security.utils.QualifierUtils;

import java.util.Optional;

/**
 * Checks whether an explicit JWKS configuration already exists for an OIDC provider.
 */
@Internal
public final class JwksUriSignatureConfigurationCondition implements Condition {

    @Override
    public boolean matches(ConditionContext context) {
        AnnotationMetadataProvider component = context.getComponent();
        Optional<String> name = QualifierUtils.nameQualifier(component);
        if (name.isEmpty()) {
            return true;
        }
        boolean missingExplicitConfiguration = context.findBean(JwksSignatureConfigurationProperties.class, Qualifiers.byName(name.get())).isEmpty();
        if (!missingExplicitConfiguration) {
            context.fail("Skipped OIDC JWKS configuration for provider [" + name.get() + "] because an explicit JWKS configuration exists");
        }
        return missingExplicitConfiguration;
    }
}
