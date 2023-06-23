//import org.openqa.selenium.firefox.FirefoxOptions
//import org.testcontainers.containers.BrowserWebDriverContainer
//import org.testcontainers.utility.DockerImageName
//import spock.util.environment.OperatingSystem
//
//driver = {
//    def isM1Mac = OperatingSystem.current.macOs && System.getProperty("os.arch") == 'aarch64'
//    def rawContainer = isM1Mac ?
//            new BrowserWebDriverContainer(DockerImageName
//                    .parse("seleniarm/standalone-firefox")
//                    .asCompatibleSubstituteFor("selenium/standalone-firefox")
//            ) :
//            new BrowserWebDriverContainer()
//
//    def container = rawContainer.withCapabilities(new FirefoxOptions())
//
//    container.start()
//    container.webDriver
//}
