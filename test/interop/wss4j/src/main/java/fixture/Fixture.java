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
import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.cxf.ws.security.wss4j.DefaultCryptoCoverageChecker;
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
        for (String profile : new String[]{"ut", "ts"}) {
            for (String version : new String[]{"11", "12"}) {
                String binding = "11".equals(version) ? SOAPBinding.SOAP11HTTP_BINDING : SOAPBinding.SOAP12HTTP_BINDING;
                EndpointImpl endpoint = new EndpointImpl(bus, new Echo(), binding);
                Map<String, Object> policy = new HashMap<>();
                policy.put(ConfigurationConstants.ACTION, "ut".equals(profile) ? "Timestamp UsernameToken" : "Timestamp");
                policy.put(ConfigurationConstants.PW_CALLBACK_REF, passwords);
                if ("ut".equals(profile)) {
                    policy.put(WSS4JInInterceptor.VALIDATOR_MAP, Map.of(org.apache.wss4j.dom.WSConstants.USERNAME_TOKEN, new FreshUsernameToken()));
                }
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
                endpoint.publish("http://0.0.0.0:8080/" + profile + version);
            }
        }
        CallbackHandler signingPassword = callbacks -> {
            for (var callback : callbacks) {
                if (!(callback instanceof WSPasswordCallback password)
                        || !java.util.Set.of("fixture-server", "fixture-server-ec256", "fixture-server-ec384", "fixture-server-ec521").contains(password.getIdentifier())) {
                    throw new java.io.IOException("Unknown synthetic signing identity");
                }
                password.setPassword("fixture-only");
            }
        };
        for (String mode : new String[]{"sig", "sigissuer", "sigx509", "sigski", "sigthumb", "sigrsa384", "sigrsa512", "sigec256", "sigec384", "sigec521", "sigecwrongcurve", "sighdr", "sighdrweak", "sigut", "sigstale", "sigfuture", "ste128", "ste256", "stefault128", "stefault256", "stehdr", "etshdr", "stehdr128", "etshdr128", "steelement128", "steelement256", "etselement128", "etselement256", "ets128", "ets256", "etsfault128", "etsfault256"}) {
            for (String version : new String[]{"11", "12"}) {
                String ns = "11".equals(version) ? "http://schemas.xmlsoap.org/soap/envelope/" : "http://www.w3.org/2003/05/soap-envelope";
                String binding = "11".equals(version) ? SOAPBinding.SOAP11HTTP_BINDING : SOAPBinding.SOAP12HTTP_BINDING;
                EndpointImpl endpoint = new EndpointImpl(bus, new Echo(), binding);
                Map<String, Object> in = new HashMap<>();
                in.put(ConfigurationConstants.ACTION, "sigut".equals(mode) ? "Timestamp UsernameToken Signature" : mode.startsWith("sig") ? "Timestamp Signature" : "Timestamp Signature Encryption");
                if ("sigut".equals(mode)) {
                    in.put(ConfigurationConstants.PW_CALLBACK_REF, passwords);
                    in.put(WSS4JInInterceptor.VALIDATOR_MAP, Map.of(org.apache.wss4j.dom.WSConstants.USERNAME_TOKEN, new FreshUsernameToken()));
                }
                if (!mode.startsWith("sig")) {
                    in.put(ConfigurationConstants.DEC_PROP_FILE, "signature.properties");
                    in.put(ConfigurationConstants.PW_CALLBACK_REF, signingPassword);
                }
                in.put(ConfigurationConstants.SIG_VER_PROP_FILE, "signature.properties");
                in.put(ConfigurationConstants.IS_BSP_COMPLIANT, "true");
                in.put(ConfigurationConstants.REQUIRE_TIMESTAMP_EXPIRES, "true");
                in.put(ConfigurationConstants.TTL_TIMESTAMP, "300");
                in.put(ConfigurationConstants.TTL_FUTURE_TIMESTAMP, "60");
                if ("sigec521".equals(mode)) {
                    in.put(ConfigurationConstants.SIG_ALGO, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");
                    in.put(ConfigurationConstants.SIG_DIGEST_ALGO, "http://www.w3.org/2001/04/xmlenc#sha512");
                    endpoint.getInInterceptors().add(new WSS4JInInterceptor(in) {
                        @Override
                        protected void setAlgorithmSuites(SoapMessage message, RequestData data) throws WSSecurityException {
                            super.setAlgorithmSuites(message, data);
                            // WSS4J's default maximum is below the standard P-521 curve.
                            data.getAlgorithmSuite().setMaximumEllipticCurveKeyLength(521);
                        }
                    });
                } else {
                    endpoint.getInInterceptors().add(new WSS4JInInterceptor(in));
                }
                DefaultCryptoCoverageChecker coverage = new DefaultCryptoCoverageChecker();
                if ("sigut".equals(mode)) {
                    // This endpoint deliberately exercises the outbound signed-token profile.
                    // Keep Body/Timestamp coverage and independently require token signing.
                    coverage.setEncryptUsernameToken(false);
                    coverage.setSignUsernameToken(true);
                }
                if (mode.startsWith("sighdr")) {
                    SignedHeaders.requireCoverage(coverage);
                    endpoint.getOutInterceptors().add(new SignedHeaders());
                    endpoint.getOutFaultInterceptors().add(new SignedHeaders());
                }
                boolean headerEncryption = mode.startsWith("stehdr") || mode.startsWith("etshdr");
                boolean elementEncryption = mode.contains("element");
                if (headerEncryption) {
                    endpoint.getOutInterceptors().add(new SignedHeaders(false));
                    endpoint.getOutFaultInterceptors().add(new SignedHeaders(false));
                }
                endpoint.getInInterceptors().add(coverage);
                Map<String, Object> out = new HashMap<>();
                out.put(ConfigurationConstants.ACTION, mode.startsWith("ste") ? "Timestamp Signature Encryption" : mode.startsWith("ets") ? "Timestamp Encryption Signature" : "Timestamp Signature");
                String signer = switch (mode) {
                    case "sigec256", "sigec384", "sigec521" -> "fixture-server-" + mode.substring(3);
                    case "sigecwrongcurve" -> "fixture-server-ec384";
                    default -> "fixture-server";
                };
                String signatureMethod = switch (mode) {
                    case "sigrsa384" -> "rsa-sha384";
                    case "sigrsa512" -> "rsa-sha512";
                    case "sigec256", "sigecwrongcurve" -> "ecdsa-sha256";
                    case "sigec384" -> "ecdsa-sha384";
                    case "sigec521" -> "ecdsa-sha512";
                    default -> "rsa-sha256";
                };
                String referenceDigest = switch (mode) {
                    case "sigrsa512", "sigec384" -> "http://www.w3.org/2001/04/xmldsig-more#sha384";
                    case "sigrsa384", "sigec521" -> "http://www.w3.org/2001/04/xmlenc#sha512";
                    default -> "http://www.w3.org/2001/04/xmlenc#sha256";
                };
                out.put(ConfigurationConstants.USER, signer);
                out.put(ConfigurationConstants.SIG_PROP_FILE, "signature.properties");
                out.put(ConfigurationConstants.PW_CALLBACK_REF, signingPassword);
                out.put(ConfigurationConstants.SIG_KEY_ID, switch (mode) {
                    case "sigissuer" -> "IssuerSerial";
                    case "sigx509" -> "X509KeyIdentifier";
                    case "sigski" -> "SKIKeyIdentifier";
                    case "sigthumb" -> "Thumbprint";
                    default -> "DirectReference";
                });
                out.put(ConfigurationConstants.SIG_ALGO, "http://www.w3.org/2001/04/xmldsig-more#" + signatureMethod);
                out.put(ConfigurationConstants.SIG_DIGEST_ALGO, referenceDigest);
                out.put(ConfigurationConstants.SIG_C14N_ALGO, "http://www.w3.org/2001/10/xml-exc-c14n#");
                out.put(ConfigurationConstants.ADD_INCLUSIVE_PREFIXES, "true");
                out.put(ConfigurationConstants.SIGNATURE_PARTS, "{Element}{" + ns + "}Body;{Element}{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp");
                if ("sighdr".equals(mode)) {
                    out.put(ConfigurationConstants.SIGNATURE_PARTS, out.get(ConfigurationConstants.SIGNATURE_PARTS) + SignedHeaders.parts());
                }
                if (!mode.startsWith("sig")) {
                    out.put(ConfigurationConstants.ENCRYPTION_USER, "fixture-client");
                    out.put(ConfigurationConstants.ENC_PROP_FILE, "signature.properties");
                    out.put(ConfigurationConstants.ENC_KEY_ID, "IssuerSerial");
                    out.put(ConfigurationConstants.ENC_SYM_ALGO, "http://www.w3.org/2009/xmlenc11#aes" + (mode.endsWith("128") ? "128" : "256") + "-gcm");
                    out.put(ConfigurationConstants.ENC_KEY_TRANSPORT, "http://www.w3.org/2009/xmlenc11#rsa-oaep");
                    out.put(ConfigurationConstants.ENC_DIGEST_ALGO, "http://www.w3.org/2001/04/xmlenc#sha256");
                    out.put(ConfigurationConstants.ENC_MGF_ALGO, "http://www.w3.org/2009/xmlenc11#mgf1sha256");
                    String encryptedPart = headerEncryption ? "{Header}{urn:trace}Trace"
                            : elementEncryption ? "{Element}{urn:xk6-soap:fixture}echoResponse" : "{Content}{" + ns + "}Body";
                    out.put(ConfigurationConstants.ENCRYPTION_PARTS, encryptedPart);
                    if (headerEncryption) {
                        String signedHeader = mode.startsWith("ets")
                                ? "{Element}{http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd}EncryptedHeader"
                                : "{Element}{urn:trace}Trace";
                        out.put(ConfigurationConstants.SIGNATURE_PARTS, out.get(ConfigurationConstants.SIGNATURE_PARTS) + ";" + signedHeader);
                    }
                    if (mode.startsWith("ets")) {
                        out.put(WSS4JOutInterceptor.WSS4J_ACTION_MAP, Map.of(org.apache.wss4j.dom.WSConstants.SIGN, new NamespaceStableSignature()));
                        out.put(ConfigurationConstants.SIGNATURE_PARTS, out.get(ConfigurationConstants.SIGNATURE_PARTS) + ";{Element}{http://www.w3.org/2001/04/xmlenc#}EncryptedKey");
                    }
                }
                if ("sigstale".equals(mode) || "sigfuture".equals(mode)) {
                    out.put(WSS4JOutInterceptor.WSS4J_ACTION_MAP,
                            Map.of(org.apache.wss4j.dom.WSConstants.TS,
                                    new OffsetTimestamp("sigstale".equals(mode) ? -600 : 120)));
                }
                endpoint.getOutInterceptors().add(new WSS4JOutInterceptor(out));
                if (elementEncryption) {
                    Map<String, Object> fault = new HashMap<>(out);
                    fault.put(ConfigurationConstants.ENCRYPTION_PARTS, "{Element}{" + ns + "}Fault");
                    endpoint.getOutFaultInterceptors().add(new WSS4JOutInterceptor(fault));
                } else if (headerEncryption || mode.startsWith("sig") || mode.startsWith("stefault") || mode.startsWith("etsfault")) {
                    endpoint.getOutFaultInterceptors().add(new WSS4JOutInterceptor(out));
                }
                endpoint.publish("http://0.0.0.0:8080/" + mode + version);
            }
        }
        Runtime.getRuntime().addShutdownHook(new Thread(() -> bus.shutdown(true)));
        System.out.println("FIXTURE_READY: CXF " + Bus.class.getPackage().getImplementationVersion()
                + " / WSS4J DOM " + org.apache.wss4j.dom.engine.WSSecurityEngine.class.getPackage().getImplementationVersion()
                + " / common " + org.apache.wss4j.common.util.DateUtil.class.getPackage().getImplementationVersion());
        new CountDownLatch(1).await();
    }
}
