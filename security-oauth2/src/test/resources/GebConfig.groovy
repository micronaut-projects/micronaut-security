import org.openqa.selenium.firefox.FirefoxDriver
import org.openqa.selenium.firefox.FirefoxOptions
import org.testcontainers.containers.BrowserWebDriverContainer
import org.testcontainers.containers.VncRecordingContainer
Closure dockerFirefoxClosure = {
    def container = new BrowserWebDriverContainer()
            .withCapabilities(new FirefoxOptions())
            .withRecordingMode(BrowserWebDriverContainer.VncRecordingMode.RECORD_ALL, new File("/Users/sdelamo/Desktop"), VncRecordingContainer.VncRecordingFormat.MP4)
    container.start()
    container.webDriver
}
Closure firefoxHeadlessClosure = {
    FirefoxOptions o = new FirefoxOptions()
    o.addArguments('-headless')
    new FirefoxDriver(o)
}
Closure firefoxClosure = {
    new FirefoxDriver()
}
driver = System.getenv('geb.env') == 'firefox' ? firefoxClosure :
        (System.getenv('geb.env') == 'firefoxHeadless' ?  firefoxHeadlessClosure : dockerFirefoxClosure)
environments {
    dockerFirefox {
        driver = dockerFirefoxClosure
    }
    firefoxHeadless {
        driver = firefoxHeadlessClosure
    }
    firefox {
        driver = firefoxClosure
    }
}
