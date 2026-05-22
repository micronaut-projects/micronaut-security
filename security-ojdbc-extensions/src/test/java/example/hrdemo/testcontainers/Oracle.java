package example.hrdemo.testcontainers;

import org.testcontainers.oracle.OracleContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.Map;

public class Oracle {
    private static final String SLIM_FASTSTART = "gvenzl/oracle-free:slim-faststart";
    private static final String IMAGE_NAME = SLIM_FASTSTART;
    private static OracleContainer container;

    public static Map<String, String> getProperties() {
        if (container == null) {
            container = new OracleContainer(DockerImageName.parse(IMAGE_NAME).asCompatibleSubstituteFor("gvenzl/oracle-free"));
            container.start();
            do {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            } while(!container.isRunning());
            return getProperties(container);
        } else {
            return getProperties(container);
        }
    }

    private static Map<String, String> getProperties(OracleContainer container) {
        return Map.of(
                "datasources.default.url", container.getJdbcUrl(),
                "datasources.default.username", container.getUsername(),
                "datasources.default.password", container.getPassword()
        );
    }
}
