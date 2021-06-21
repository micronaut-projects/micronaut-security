import org.openqa.selenium.firefox.FirefoxOptions
import org.testcontainers.containers.BrowserWebDriverContainer

driver = {
    def container = new BrowserWebDriverContainer()
            .withCapabilities(new FirefoxOptions())
    container.start()
    container.webDriver
}