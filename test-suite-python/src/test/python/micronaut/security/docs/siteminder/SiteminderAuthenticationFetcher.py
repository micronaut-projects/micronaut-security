# tag::clazz[]
from jakarta.inject import Singleton
from micronaut.context.annotation import Requires
from micronaut.core.util import StringUtils
from micronaut.http import HttpRequest
from micronaut.security.authentication import Authentication
from micronaut.security.filters import AuthenticationFetcher
from org.reactivestreams import Publisher
from reactor.core.publisher import Mono
# end::clazz[]

SITEMINDER_USER_HEADER = "SM_USER"


@Requires(property="spec.name", value="SiteminderAuthorizationTest")
# tag::clazz[]
@Singleton
class SiteminderAuthenticationFetcher(AuthenticationFetcher[HttpRequest]):

    SITEMINDER_USER_HEADER = "SM_USER"

    def fetchAuthentication(self, request: HttpRequest) -> Publisher[Authentication]:
        def fetch(emitter):
            siteminderUser = request.getHeaders().get(self.SITEMINDER_USER_HEADER)
            if StringUtils.isEmpty(siteminderUser):
                emitter.success()
                return

            roles = ["ROLE_USER"]
            emitter.success(Authentication.build(siteminderUser, roles))

        return Mono.create(fetch)
# end::clazz[]
