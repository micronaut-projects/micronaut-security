import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import org.openqa.selenium.firefox.FirefoxDriver
import org.openqa.selenium.htmlunit.HtmlUnitDriver

// default is to use htmlunit
driver = {
    HtmlUnitDriver htmlUnitDriver = new HtmlUnitDriver()
    htmlUnitDriver.javascriptEnabled = true
    htmlUnitDriver
}

environments {
    chrome { driver = { new ChromeDriver() } }

    chromeHeadless {
        driver = {
            ChromeOptions o = new ChromeOptions()
            o.addArguments('headless')
            new ChromeDriver(o)
        }
    }

    // default is to use htmlunit
    driver = {
        HtmlUnitDriver htmlUnitDriver = new HtmlUnitDriver()
        htmlUnitDriver.javascriptEnabled = true
        htmlUnitDriver
    }

    firefox { driver = { new FirefoxDriver() } }
}
