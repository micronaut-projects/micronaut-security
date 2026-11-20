package io.micronaut.security.docs.cspnonce;

import io.micronaut.context.annotation.Requires;
//tag::clazz[]
import io.micronaut.http.HttpRequest;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import io.micronaut.views.ModelAndView;
import io.micronaut.views.model.ViewModelProcessor;
import jakarta.inject.Singleton;

import java.util.HashMap;
import java.util.Map;

//end::clazz[]
@Requires(property = "spec.name", value = "CspNonceViewModelProcessorTest")
//tag::clazz[]
@Singleton
class CspNonceViewModelProcessor implements ViewModelProcessor<Map<String, Object>, HttpRequest<?>> {

    @Override
    public void process(HttpRequest<?> request, ModelAndView<Map<String, Object>> modelAndView) {
        request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class)
            .ifPresent(nonce -> modelAndView.getModel().ifPresent(model -> {
                Map<String, Object> mutableModel = new HashMap<>(model);
                mutableModel.put(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, nonce);
                modelAndView.setModel(mutableModel);
            }));
    }
}
//end::clazz[]
