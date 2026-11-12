import org.openqa.selenium.firefox.FirefoxDriver
import org.openqa.selenium.firefox.FirefoxOptions
import org.testcontainers.containers.BrowserWebDriverContainer
import org.testcontainers.utility.DockerImageName
import spock.util.environment.OperatingSystem

Closure firefoxDriver = { ->
    if (System.getProperty("geb.env") == "dockerFirefox") {
        boolean isM1Mac = OperatingSystem.current.macOs && System.getProperty("os.arch") == 'aarch64'
        BrowserWebDriverContainer rawContainer = isM1Mac ?
                new BrowserWebDriverContainer(DockerImageName
                        .parse("seleniarm/standalone-firefox")
                        .asCompatibleSubstituteFor("selenium/standalone-firefox")
                ) :
                new BrowserWebDriverContainer()
        BrowserWebDriverContainer container = rawContainer.withCapabilities(new FirefoxOptions())
        container.start()
        return container.webDriver
    }
    new FirefoxDriver()
}
driver = {
    firefoxDriver()
}
