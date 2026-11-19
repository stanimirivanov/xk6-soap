package fixture;

import jakarta.jws.WebMethod;
import jakarta.jws.WebParam;
import jakarta.jws.WebService;
import jakarta.xml.ws.soap.SOAPBinding;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.CountDownLatch;
import javax.security.auth.callback.CallbackHandler;
import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.wss4j.common.cache.MemoryReplayCache;

/** Local-only synthetic service. Apache CXF/WSS4J owns all security validation. */
public final class Fixture {
    @WebService(targetNamespace = "urn:xk6-soap:fixture", serviceName = "FixtureService")
    public static class Echo {
        @WebMethod(action = "urn:echo")
        public String echo(@WebParam(name = "value") String value) {
            if ("fault".equals(value)) {
                throw new jakarta.xml.ws.WebServiceException("Synthetic service fault");
            }
            return value;
        }
    }

    public static void main(String[] args) throws Exception {
        Bus bus = BusFactory.newInstance().createBus();
        BusFactory.setDefaultBus(bus);
        CallbackHandler passwords = callbacks -> {
            for (var callback : callbacks) {
                if (!(callback instanceof WSPasswordCallback password)
                        || !"fixture-user".equals(password.getIdentifier())) {
                    throw new java.io.IOException("Unknown synthetic identity");
                }
                password.setPassword("fixture-password");
            }
        };
        for (String version : new String[]{"11", "12"}) {
            String binding = "11".equals(version) ? SOAPBinding.SOAP11HTTP_BINDING : SOAPBinding.SOAP12HTTP_BINDING;
            EndpointImpl endpoint = new EndpointImpl(bus, new Echo(), binding);
            Map<String, Object> policy = new HashMap<>();
            policy.put(ConfigurationConstants.ACTION, "Timestamp UsernameToken");
            policy.put(ConfigurationConstants.PW_CALLBACK_REF, passwords);
            policy.put(ConfigurationConstants.IS_BSP_COMPLIANT, "true");
            policy.put(ConfigurationConstants.TIMESTAMP_STRICT, "true");
            policy.put(ConfigurationConstants.REQUIRE_TIMESTAMP_EXPIRES, "true");
            policy.put(ConfigurationConstants.TTL_TIMESTAMP, "300");
            policy.put(ConfigurationConstants.TTL_FUTURE_TIMESTAMP, "60");
            policy.put(ConfigurationConstants.TTL_USERNAMETOKEN, "300");
            policy.put(ConfigurationConstants.TTL_FUTURE_USERNAMETOKEN, "60");
            endpoint.getProperties().put(SecurityConstants.ENABLE_NONCE_CACHE, Boolean.TRUE);
            endpoint.getProperties().put(SecurityConstants.NONCE_CACHE_INSTANCE, new MemoryReplayCache());
            endpoint.getInInterceptors().add(new WSS4JInInterceptor(policy));
            endpoint.publish("http://0.0.0.0:8080/ut" + version);
        }
        Runtime.getRuntime().addShutdownHook(new Thread(() -> bus.shutdown(true)));
        System.out.println("FIXTURE_READY: CXF 4.2.4 / WSS4J 4.0.2");
        new CountDownLatch(1).await();
    }
}
