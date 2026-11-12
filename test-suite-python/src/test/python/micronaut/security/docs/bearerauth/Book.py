from dataclasses import dataclass

from micronaut.serde.annotation import Serdeable


@Serdeable
@dataclass
class Book:
    isbn: str
    name: str
