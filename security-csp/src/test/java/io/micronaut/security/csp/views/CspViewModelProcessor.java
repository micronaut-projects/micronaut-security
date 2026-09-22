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
package io.micronaut.security.csp.views;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import io.micronaut.views.ModelAndView;
import io.micronaut.views.model.ViewModelProcessor;
import jakarta.inject.Singleton;

import java.util.HashMap;
import java.util.Map;

/**
 * Adds the request's CSP nonce to map-backed view models.
 *
 * <p>When a nonce is available, it is exposed as {@code cspNonce} so a view can apply it to
 * trusted {@code script} elements. The processor copies the model before adding the value, so it
 * also supports immutable input maps.</p>
 */
@Requires(classes = ViewModelProcessor.class)
@Singleton
@Internal
final class CspViewModelProcessor implements ViewModelProcessor<Map<String, Object>, HttpRequest<?>> {
    /**
     * Copies a map-backed model and adds the request nonce when one has been generated.
     *
     * @param request the request carrying the nonce attribute
     * @param modelAndView the view model to enrich
     */
    @Override
    public void process(HttpRequest<?> request, ModelAndView<Map<String, Object>> modelAndView) {
        request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).ifPresent(nonce -> {
            modelAndView.getModel().ifPresent(model -> {
                Map<String, Object> mutableModel = new HashMap<>(model);
                mutableModel.put(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, nonce);
                modelAndView.setModel(mutableModel);
            });
        });
    }
}
