package io.micronaut.security.docs.cspnonce

import io.micronaut.context.annotation.Requires
//tag::clazz[]
import io.micronaut.http.HttpRequest
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator
import io.micronaut.views.ModelAndView
import io.micronaut.views.model.ViewModelProcessor
import jakarta.inject.Singleton

//end::clazz[]
@Requires(property = "spec.name", value = "CspNonceViewModelProcessorTest")
//tag::clazz[]
@Singleton
class CspNonceViewModelProcessor : ViewModelProcessor<Map<String, Any>, HttpRequest<*>> {

    override fun process(request: HttpRequest<*>, modelAndView: ModelAndView<Map<String, Any>>) {
        request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String::class.java).ifPresent { nonce ->
            modelAndView.model.ifPresent { model ->
                modelAndView.setModel(model + (ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE to nonce))
            }
        }
    }
}
//end::clazz[]
