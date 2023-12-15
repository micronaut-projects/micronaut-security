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
package io.micronaut.security.audit;

import io.micronaut.context.annotation.Requires;
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
import io.micronaut.security.annotation.CreatedBy;
import io.micronaut.security.annotation.UpdatedBy;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.utils.SecurityService;
import jakarta.inject.Singleton;

import java.lang.annotation.Annotation;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Stream;

/**
 * An event listener that handles auto-population of entity fields annotated with {@link CreatedBy} or
 * {@link UpdatedBy} by mapping them from the current {@link Authentication}.
 *
 * @author Jeremy Grelle
 * @since 4.5.0
 */
@Requires(classes = { AutoPopulatedEntityEventListener.class, EntityEventContext.class })
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
        populate(context, PrePersist.class);
        return true;
    }

    @Override
    public boolean preUpdate(@NonNull EntityEventContext<Object> context) {
        populate(context, PreUpdate.class);
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

    private void populate(@NonNull EntityEventContext<Object> context,
                          @NonNull Class<? extends Annotation> listenerAnnotation) {
        securityService.getAuthentication().ifPresent(authentication -> {
            Map<Class<?>, Object> valueForType = new HashMap<>();
            Stream.of(getApplicableProperties(context.getPersistentEntity()))
                    .filter(persistentProperty -> shouldSetProperty(persistentProperty, listenerAnnotation))
                    .forEach(persistentProperty -> {
                        final BeanProperty<Object, Object> beanProperty = persistentProperty.getProperty();
                        Object value = valueForType.computeIfAbsent(beanProperty.getType(), type -> conversionService.convert(authentication, beanProperty.getType()).orElse(null));
                        context.setProperty(beanProperty, value);
                    });
        });
    }

    private boolean shouldSetProperty(@NonNull RuntimePersistentProperty<Object> persistentProperty, Class<? extends Annotation> listenerAnnotation) {
        if (listenerAnnotation == PrePersist.class) {
            return true;
        }
        if (listenerAnnotation == PreUpdate.class) {
            return persistentProperty.getAnnotationMetadata().booleanValue(AutoPopulated.class, AutoPopulated.UPDATEABLE).orElse(true);
        }
        return false;
    }
}
