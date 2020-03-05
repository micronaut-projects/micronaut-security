
import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import org.openqa.selenium.firefox.FirefoxDriver
import org.openqa.selenium.htmlunit.HtmlUnitDriver

environments {
    chrome { driver = { new ChromeDriver() } }

    chromeHeadless {
        driver = {
            ChromeOptions o = new ChromeOptions()
            o.addArguments('headless')
            new ChromeDriver(o)
        }
    }

    htmlunit { driver = { new HtmlUnitDriver(true) } }

    firefox { driver = { new FirefoxDriver() } }
}
