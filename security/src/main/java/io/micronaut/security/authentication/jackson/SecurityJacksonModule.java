/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.authentication.jackson;

import com.fasterxml.jackson.databind.module.SimpleAbstractTypeResolver;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.micronaut.core.annotation.TypeHint;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.DefaultAuthentication;

import jakarta.inject.Singleton;

/**
 * A module to extend Jackson for security related classes.
 *
 * @author James Kleeh
 * @since 1.0
 */
@Singleton
@TypeHint(typeNames = {
        "com.fasterxml.jackson.databind.PropertyNamingStrategy$SnakeCaseStrategy"
})
public class SecurityJacksonModule extends SimpleModule {

    /**
     * Default constructor.
     */
    public SecurityJacksonModule() {
        super("micronaut.security");
        SimpleAbstractTypeResolver resolver = new SimpleAbstractTypeResolver();
        resolver.addMapping(Authentication.class, DefaultAuthentication.class);
        this._abstractTypes = resolver;
    }
}
