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

package io.micronaut.security.oauth2.openid.endpoints.endsession;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.views.ModelAndView;
import io.micronaut.views.model.ViewModelProcessor;

import javax.annotation.Nonnull;
import javax.inject.Singleton;
import java.util.HashMap;
import java.util.Map;

/**
 * {@link ViewModelProcessor} which adds to the model the end session url.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Requires(beans = {
        EndsessionViewModelProcessorConfiguration.class,
        EndSessionUrlProvider.class
})
@Requires(classes = ViewModelProcessor.class)
@Singleton
public class EndsessionViewModelProcessor implements ViewModelProcessor {

    private final EndsessionViewModelProcessorConfiguration endsessionViewModelProcessorConfiguration;
    private final EndSessionUrlProvider endSessionUrlProvider;

    /**
     *
     * @param endsessionViewModelProcessorConfiguration {@link EndsessionViewModelProcessor} Configuration.
     * @param endSessionUrlProvider End session url provider
     */
    public EndsessionViewModelProcessor(EndsessionViewModelProcessorConfiguration endsessionViewModelProcessorConfiguration,
                                        EndSessionUrlProvider endSessionUrlProvider) {
        this.endsessionViewModelProcessorConfiguration = endsessionViewModelProcessorConfiguration;
        this.endSessionUrlProvider = endSessionUrlProvider;
    }

    @Override
    public void process(@Nonnull HttpRequest<?> request, @Nonnull ModelAndView<Map<String, Object>> modelAndView) {
        Map<String, Object> viewModel = modelAndView.getModel().orElseGet(() -> {
            final HashMap<String, Object> newModel = new HashMap<>(1);
            modelAndView.setModel(newModel);
            return newModel;
        });
        viewModel.putIfAbsent(endsessionViewModelProcessorConfiguration.getEndSessionUrlKey(), endSessionUrlProvider.resolveLogoutUrl(request));
    }
}
