/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.audit.event.listeners;

import io.micronaut.core.annotation.AnnotationMetadata;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.beans.BeanProperty;
import io.micronaut.core.convert.ConversionService;
import io.micronaut.data.annotation.AutoPopulated;
import io.micronaut.data.annotation.event.PrePersist;
import io.micronaut.data.annotation.event.PreUpdate;
import io.micronaut.data.event.EntityEventContext;
import io.micronaut.data.model.runtime.RuntimePersistentProperty;
import io.micronaut.data.runtime.event.listeners.AutoPopulatedEntityEventListener;
import io.micronaut.security.audit.annotation.CreatedBy;
import io.micronaut.security.audit.annotation.UpdatedBy;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.utils.SecurityService;
import jakarta.inject.Singleton;

import java.lang.annotation.Annotation;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * An event listener that handles auto-population of entity fields annotated with {@link CreatedBy} or
 * {@link UpdatedBy} by mapping them from the current {@link Authentication}.
 *
 * @author Jeremy Grelle
 * @since 4.5.0
 */
@Singleton
public class UserAuditingEntityEventListener extends AutoPopulatedEntityEventListener {

    private final SecurityService securityService;

    private final ConversionService conversionService;

    UserAuditingEntityEventListener(SecurityService securityService, ConversionService conversionService) {
        this.securityService = securityService;
        this.conversionService = conversionService;
    }

    @Override
    public boolean prePersist(@NonNull EntityEventContext<Object> context) {
        autoPopulateUserIdentity(context, false);
        return true;
    }

    @Override
    public boolean preUpdate(@NonNull EntityEventContext<Object> context) {
        autoPopulateUserIdentity(context, true);
        return true;
    }

    @Override
    protected @NonNull List<Class<? extends Annotation>> getEventTypes() {
        return Arrays.asList(PrePersist.class, PreUpdate.class);
    }

    @Override
    protected @NonNull Predicate<RuntimePersistentProperty<Object>> getPropertyPredicate() {
        return property -> {
            final AnnotationMetadata annotationMetadata = property.getAnnotationMetadata();
            return annotationMetadata.hasAnnotation(CreatedBy.class) || annotationMetadata.hasAnnotation(UpdatedBy.class);
        };
    }

    private void autoPopulateUserIdentity(@NonNull EntityEventContext<Object> context, boolean isUpdate) {
        final RuntimePersistentProperty<Object>[] applicableProperties = getApplicableProperties(context.getPersistentEntity());
        for (RuntimePersistentProperty<Object> persistentProperty : applicableProperties) {
            if (isUpdate) {
                if (!persistentProperty.getAnnotationMetadata().booleanValue(AutoPopulated.class, AutoPopulated.UPDATEABLE).orElse(true)) {
                    continue;
                }
            }

            final BeanProperty<Object, Object> beanProperty = persistentProperty.getProperty();
            getCurrentUserIdentityForProperty(beanProperty).ifPresent(identity -> context.setProperty(beanProperty, identity));
        }
    }

    private Optional<Object> getCurrentUserIdentityForProperty(BeanProperty<Object, Object> beanProperty) {
        return securityService.getAuthentication().flatMap(authentication -> conversionService.convert(authentication, beanProperty.getType()));
    }
}
