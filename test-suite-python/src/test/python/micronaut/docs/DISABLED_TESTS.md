# Python Docs Disabled Test Inventory

This file tracks Python docs examples of Micronaut Security that are present but disabled, or that deviate from the
Java example because the direct port currently fails compilation or at runtime. Use it as the bug-fixing task list
for the final migration wave.

## Reconciliation

- Last generated active `@Disabled` count: 0.
- Last generated command: `rg -n "@Disabled\\(" test-suite-python/src/test/python`.
- Last full-suite command: `./gradlew :test-suite-python:test -Ppython-ci --max-workers=1`.
- Last full-suite result: build successful, 30 tests executed (`ClientCredentialsClientOfTest` skips itself without Docker).

## Migration Rules

- Do not define local copies of Micronaut annotation helpers or custom annotation shims in docs snippets. Standard
  Micronaut annotations are generated from imports. If Python cannot express the import path, keep the intended
  annotation commented out with a TODO and track it below.
- Do not add Java-style getters or setters to Python docs models. Prefer `@dataclass` models with idiomatic Python
  attributes.
- Prefer `@MicronautTest` with injected beans over `ApplicationContext.run()` unless the snippet documents manual
  context creation or a Python compiler limitation requires it (see below).
- Methods that implement or override a Java interface keep the Java (camelCase) name; other methods are snake_case.
- A Python class cannot extend a Java class ("Native Python mode does not support Python class [...] extending Java
  class"). Examples that extend a Java class in Java/Kotlin/Groovy are ported with composition: implement the Java
  interface and delegate to an instance of the Java class (`MyRejectionHandler`), or re-implement the interface
  (`SensitiveEndpointRuleReplacement`, which implements `SecurityRule` + `EndpointSensitivityHandler` instead of
  extending `SensitiveEndpointRule`).
- Import Java classes with normal Python imports (`from reactor.core.publisher import Mono`, `from java.util import List`,
  `from micronaut.http import HttpStatus`, nested classes as `from micronaut.core.bind.ArgumentBinder import BindingResult`).
  Imported Java *classes* and the `java.util` interfaces are also accepted as runtime type arguments (`Argument.of(Map)`,
  `List.of(...)`, `java.instanceof(x, RSAEncryption)`, `java.instanceof(x, EncryptedJWT)`), but an imported Micronaut
  *interface* is a `_MicronautJavaType` wrapper that `java.instanceof()`, `getBean()` and `getUserPrincipal()` reject.
  `java.type("...")` is used only where the import form fails (see "java.type usages" below), each marked with a
  `# TODO(python)` comment.
- Use Python's `logging` module for log output (`LOG = logging.getLogger(__name__)`), not slf4j.
- Overloaded Java methods taking `Collection` and `Map` (`AuthenticationResponse.success(String, Collection)` vs
  `success(String, Map)`) pick the `Map` overload for a Python `list`; pass `java.util.List.of(...)` instead.
- Python sources cannot live in a package that shadows a Java package that is imported (`micronaut.security.oauth2.client.clientcredentials`);
  `ClientCredentialsClientOfTest` was moved to `io.micronaut.security.oauth2.docs.clientcredentials` in every language.

## Active `@Disabled` Tests

None.

## Commented Unsupported Snippet Ports

| Target | Reason |
| --- | --- |
| `io.micronaut.security.oauth2.docs.github.GithubUser` | The Java example uses `@Introspected` + Jackson 3 `@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)`; importing `tools.jackson.databind.annotation.JsonNaming` makes the Python compiler overflow its stack (`PythonAnnotationMetadataBuilder.findDecoratorDef` recursion). The Python class uses `@Serdeable(naming=SnakeCaseStrategy)` from Micronaut Serialization instead. |

## Workarounds Kept In Tests

| Test | Reason |
| --- | --- |
| `io.micronaut.security.audit.docs.customconverter.CustomPrincipalConverterTest` | A Python `TypeConverter` bean is instantiated by `DefaultApplicationContext.initializeTypeConverters()` before the `@Context` GraalPy context bean exists ("GraalPy context has not been initialized"). The test starts the application context under test from an outer `@MicronautTest` context (whose Python runtime is reused) with `ApplicationContext.run(...)`. |
| `io.micronaut.security.oauth2.docs.clientcredentials.ClientCredentialsClientOfTest` | Class-level JUnit annotations other than `@MicronautTest`/`@Property` (`@Testcontainers(disabledWithoutDocker = true)`) are not emitted on the generated test class, and a Python test needs the GraalPy runtime of a Micronaut context. The test is `@MicronautTest(startApplication = false)` and skips itself with `Assumptions.assumeTrue(DockerClientFactory.instance().isDockerAvailable())`. |

## java.type usages

Remaining `java.type(...)` calls (all marked with `# TODO(python): java.type needed because ...`):

| Test | Usage | Reason |
| --- | --- | --- |
| `io.micronaut.security.docs.bearerauth.BearerAuthTest` | `Argument.listOf(BookClass)` | A Python class (`Book`) is passed as a runtime type argument; the Python class object itself is not accepted as a Java `Class`. |
| `io.micronaut.security.docs.customauthentication.AuthenticationWithEmailArgumentBinder` | `Argument.of(AuthenticationWithEmailClass)` | A Python class (`AuthenticationWithEmail`) is passed as a runtime type argument. |
| `io.micronaut.security.websocket.AuthenticationWebSocketStateBinderSpec` | `WebSocketClient.connect(AuthenticationEchoClientWebSocketClass, request)` | A Python class (`AuthenticationEchoClientWebSocket`) is passed as a runtime type argument. |
| `io.micronaut.security.audit.docs.customconverter.CustomPrincipalConverterTest` | `ApplicationContext.getBean(BookRepositoryClass)` | A Python `@JdbcRepository` interface (`BookRepository`) is looked up by type; an imported Python class is not usable as the bean lookup type. |
| `io.micronaut.security.docs.clientcredentials.ClientCredentialsClientTest` | `ApplicationContext.getBean(ClientCredentialsClient, Qualifiers.byName(...))` | The imported Java interface is a `_MicronautJavaType` wrapper: `UnsupportedOperationException: Unsupported operation identifier 'getType' ... type: _MicronautJavaType`. |
| `io.micronaut.security.docs.customauthentication.AuthenticationWithEmailArgumentBinder` | `HttpRequest.getUserPrincipal(AuthenticationClass)` | The imported `Authentication` interface is not accepted as the principal type: `TypeError: invalid instantiation of foreign object`. |
| `io.micronaut.security.docs.managementendpoints.SensitiveEndpointRuleReplacement` | `java.instanceof(routeMatch, MethodBasedRouteMatch)` | The imported `MethodBasedRouteMatch` interface is rejected: `ValueError: instanceof second argument '_MicronautJavaType' is not a Java class`. |
| `io.micronaut.security.docs.sensitiveendpointrule.SensitiveEndpointRuleReplacement` | `java.instanceof(routeMatch, MethodBasedRouteMatch)` | Same as above. |

## Intentionally Unsupported Snippet Targets

None.
