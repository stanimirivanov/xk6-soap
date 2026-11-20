package fixture;

import java.util.List;
import java.util.Map;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.headers.Header;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.ws.security.wss4j.CryptoCoverageChecker.XPathExpression;
import org.apache.cxf.ws.security.wss4j.CryptoCoverageUtil.CoverageType;
import org.apache.cxf.ws.security.wss4j.DefaultCryptoCoverageChecker;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Independent DOM construction; WSS4J selects and signs these blocks itself. */
public final class SignedHeaders extends AbstractSoapInterceptor {
    private static final String WSA = "http://www.w3.org/2005/08/addressing";

    public SignedHeaders() {
        super(Phase.PRE_PROTOCOL);
        addBefore(WSS4JOutInterceptor.class.getName());
    }

    public static void requireCoverage(DefaultCryptoCoverageChecker coverage) {
        coverage.addPrefixes(Map.of("trace", "urn:trace"));
        for (String envelope : new String[]{"soapenv", "soapenv12"}) {
            for (String block : new String[]{"trace:Trace", "wsa:Action", "wsa:To", "wsa:MessageID", "wsa:ReplyTo"}) {
                coverage.addXPaths(List.of(new XPathExpression("/" + envelope + ":Envelope/" + envelope + ":Header/" + block, CoverageType.SIGNED)));
            }
        }
    }

    public static String parts() {
        return ";{Element}{urn:trace}Trace;{Element}{" + WSA + "}Action;{Element}{" + WSA
                + "}To;{Element}{" + WSA + "}MessageID;{Element}{" + WSA + "}ReplyTo";
    }

    @Override
    public void handleMessage(SoapMessage message) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            Document doc = factory.newDocumentBuilder().newDocument();
            add(message, doc, "urn:trace", "Trace", "response-original");
            add(message, doc, WSA, "Action", "urn:echoResponse");
            add(message, doc, WSA, "To", WSA + "/anonymous");
            add(message, doc, WSA, "MessageID", "urn:uuid:synthetic-response");
            Element reply = add(message, doc, WSA, "ReplyTo", null);
            Element address = doc.createElementNS(WSA, "h:Address");
            address.setTextContent(WSA + "/anonymous");
            reply.appendChild(address);
        } catch (javax.xml.parsers.ParserConfigurationException e) {
            throw new org.apache.cxf.interceptor.Fault(e);
        }
    }

    private static Element add(SoapMessage message, Document doc, String namespace, String local, String value) {
        Element block = doc.createElementNS(namespace, "h:" + local);
        block.setAttributeNS(javax.xml.XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:h", namespace);
        if (value != null) {
            block.setTextContent(value);
        }
        message.getHeaders().add(new Header(new QName(namespace, local), block));
        return block;
    }
}
