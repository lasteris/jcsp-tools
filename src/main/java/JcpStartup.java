import io.quarkus.runtime.Startup;
import jakarta.annotation.PostConstruct;
import ru.CryptoPro.JCSP.JCSP;

import java.security.Security;

@Startup
public class JcpStartup {

    @PostConstruct
    void init() {
        Security.addProvider(new JCSP());
    }

}
