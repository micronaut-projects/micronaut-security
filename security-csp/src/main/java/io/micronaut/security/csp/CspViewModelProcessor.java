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
package io.micronaut.security.csp;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpRequest;
import io.micronaut.views.ModelAndView;
import io.micronaut.views.model.ViewModelProcessor;
import jakarta.inject.Singleton;

import java.util.HashMap;
import java.util.Map;

/**
 * Adds the request's CSP nonce to map-backed view models.
 */
@Requires(classes = ViewModelProcessor.class)
@Singleton
@Internal
final class CspViewModelProcessor implements ViewModelProcessor<Map<String, Object>, HttpRequest<?>> {
    @Override
    public void process(HttpRequest<?> request, ModelAndView<Map<String, Object>> modelAndView) {
        request.getAttribute(CspNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).ifPresent(nonce -> {
            modelAndView.getModel().ifPresent(model -> {
                Map<String, Object> mutableModel = new HashMap<>(model);
                mutableModel.put(CspNonceGenerator.CSP_NONCE_ATTRIBUTE, nonce);
                modelAndView.setModel(mutableModel);
            });
        });
    }
}
