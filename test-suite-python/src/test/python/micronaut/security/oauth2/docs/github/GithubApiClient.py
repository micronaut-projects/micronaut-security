# tag::clazz[]
from abc import ABC, abstractmethod
from typing import Annotated

from micronaut.http.annotation import Get, Header
from micronaut.http.client.annotation import Client
from org.reactivestreams import Publisher

from .GithubUser import GithubUser


@Header(name="User-Agent", value="Micronaut")
@Client("https://api.github.com")
class GithubApiClient(ABC):

    @Get("/user")
    @abstractmethod
    def get_user(self, authorization: Annotated[str, Header("Authorization")]) -> Publisher[GithubUser]:
        ...
# end::clazz[]
