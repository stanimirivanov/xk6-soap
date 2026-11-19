package fixture;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.UsernameTokenValidator;

/** The selected fixture profile requires nonce and Created for Digest AND Text.
 * Apache still owns password verification, freshness and nonce replay handling.
 */
public final class FreshUsernameToken extends UsernameTokenValidator {
    @Override
    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        if (credential == null || credential.getUsernametoken() == null
                || credential.getUsernametoken().getCreated() == null
                || credential.getUsernametoken().getCreated().isEmpty()
                || credential.getUsernametoken().getNonce() == null
                || credential.getUsernametoken().getNonce().isEmpty()) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
        }
        return super.validate(credential, data);
    }
}
