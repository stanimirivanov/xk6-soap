package fixture;

import javax.xml.XMLConstants;
import org.apache.wss4j.common.SecurityActionToken;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.action.SignatureAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandler;
import org.w3c.dom.Element;

/** Materialize the declarations SOAP serialization would otherwise add after signing.
 * WSS4J 4.0.2 WSSecEncryptedKey.createEncryptedKey creates prefixed DigestMethod
 * and MGF elements without xmlns attributes. Canonicalization assumes a namespace-
 * complete DOM; signing this incomplete DOM produces an invalid wire EK digest.
 * All signing/canonicalization/crypto remains Apache's, with no relaxed checks.
 */
public final class NamespaceStableSignature extends SignatureAction {
    @Override
    public void execute(WSHandler handler, SecurityActionToken token, RequestData data)
            throws WSSecurityException {
        var document = data.getSecHeader().getSecurityHeaderDoc();
        var keys = document.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedKey");
        for (int i = 0; i < keys.getLength(); i++) {
            var key = (Element) keys.item(i);
            declare(key, "http://www.w3.org/2000/09/xmldsig#", "DigestMethod");
            declare(key, "http://www.w3.org/2009/xmlenc11#", "MGF");
        }
        super.execute(handler, token, data);
    }

    private static void declare(Element parent, String namespace, String local) {
        var nodes = parent.getElementsByTagNameNS(namespace, local);
        for (int i = 0; i < nodes.getLength(); i++) {
            var element = (Element) nodes.item(i);
            element.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI,
                    "xmlns:" + element.getPrefix(), namespace);
        }
    }
}
