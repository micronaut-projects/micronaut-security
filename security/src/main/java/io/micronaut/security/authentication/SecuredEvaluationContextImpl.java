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
package io.micronaut.security.authentication;

import io.micronaut.security.annotation.SecuredEvaluationContext;
import jakarta.inject.Singleton;

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@Singleton
public class SecuredEvaluationContextImpl implements SecuredEvaluationContext {
    @Override
    public Principal getPrincipal() {
        return () -> "Dean";
    }

//    private final Authentication authentication;
//
//    public SecuredEvaluationContextImpl(Authentication authentication) {
//        this.authentication = authentication;
//    }
//
//    @Override
//    public Map<String, Object> getAttributes() {
//        return authentication.getAttributes();
////        return Collections.emptyMap();
//    }
//
//    @Override
//    public String getName() {
//        return authentication.getName();
////        return "";
//    }
//
//    @Override
//    public Collection<String> getRoles() {
//    return authentication.getRoles();
////        return Collections.emptyList();
//    }

}
