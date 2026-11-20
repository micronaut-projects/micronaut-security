from micronaut.context.annotation import Requires

# tag::imports[]
from typing import Optional

from jakarta.inject import Singleton
from micronaut.core.order import Ordered
from micronaut.http import HttpRequest, SecFetch
from micronaut.security.fetchmetadata import FetchMetadataRuleResult, HttpRequestFetchMetadataRule
# end::imports[]


@Requires(property="spec.name", value="PublicResourceFetchMetadataRuleTest")
# tag::clazz[]
@Singleton
class PublicResourceFetchMetadataRule(HttpRequestFetchMetadataRule):

    def check(self, request: HttpRequest, secFetch: Optional[SecFetch]) -> FetchMetadataRuleResult:
        if request.getPath() == "/favicon.ico":
            return FetchMetadataRuleResult.ALLOWED
        return FetchMetadataRuleResult.UNKNOWN

    def getOrder(self) -> int:
        return Ordered.HIGHEST_PRECEDENCE
# end::clazz[]
