# tag::clazz[]
from dataclasses import dataclass

from micronaut.serde.annotation import Serdeable
from micronaut.serde.config.naming import SnakeCaseStrategy


@Serdeable(naming=SnakeCaseStrategy)
@dataclass
class GithubUser:
    login: str | None = None
    name: str | None = None
    email: str | None = None
# end::clazz[]
# TODO(python): the Java example uses @Introspected with Jackson's @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy);
# importing tools.jackson.databind.annotation.JsonNaming makes the Python compiler overflow its stack, so the
# Micronaut Serialization naming strategy is used instead.
