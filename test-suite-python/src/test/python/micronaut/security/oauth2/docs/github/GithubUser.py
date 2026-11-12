# tag::clazz[]
from dataclasses import dataclass

from micronaut.core.annotation import Introspected
from tools.jackson.databind import PropertyNamingStrategies
from tools.jackson.databind.annotation import JsonNaming


@Introspected
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy)
@dataclass
class GithubUser:
    login: str | None = None
    name: str | None = None
    email: str | None = None
# end::clazz[]
