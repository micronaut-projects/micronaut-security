# tag::clazz[]
from jakarta.inject import Singleton
from java.util import HashMap, Map
from micronaut.context.annotation import Requires
from micronaut.http import HttpRequest
from micronaut.security.csp.nonce import ContentSecurityPolicyNonceGenerator
from micronaut.views import ModelAndView
from micronaut.views.model import ViewModelProcessor

# end::clazz[]
@Requires(property="spec.name", value="CspNonceViewModelProcessorTest")
# tag::clazz[]
@Singleton
class CspNonceViewModelProcessor(ViewModelProcessor[Map[str, object], HttpRequest]):

    def process(self, request: HttpRequest, modelAndView: ModelAndView[Map[str, object]]) -> None:
        nonce = request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE).orElse(None)
        model = modelAndView.getModel().orElse(None)
        if nonce is not None and model is not None:
            mutableModel = HashMap(model)
            mutableModel.put(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, nonce)
            modelAndView.setModel(mutableModel)
# end::clazz[]
