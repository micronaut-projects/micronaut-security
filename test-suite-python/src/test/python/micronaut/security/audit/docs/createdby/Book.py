# tag::clazz[]
from dataclasses import dataclass
from typing import Annotated

from jakarta.validation.constraints import NotBlank
from micronaut.data.annotation import GeneratedValue, Id, MappedEntity
from micronaut.security.annotation import CreatedBy, UpdatedBy


@MappedEntity  # <1>
@dataclass
class Book:
    id: Annotated[int | None, Id, GeneratedValue]
    title: Annotated[str, NotBlank]
    author: Annotated[str, NotBlank]
    creator: Annotated[str | None, CreatedBy]  # <2>
    editor: Annotated[str | None, UpdatedBy]  # <3>
# end::clazz[]
