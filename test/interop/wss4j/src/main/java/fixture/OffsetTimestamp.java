package fixture;

import org.apache.wss4j.common.SecurityActionToken;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.action.TimestampAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandler;
import org.apache.wss4j.dom.message.WSSecTimestamp;

/** Test-only clock for Apache-produced timestamps, applied before Apache signs.
 * The request-local builder never mutates the endpoint's shared WSSConfig.
 */
public final class OffsetTimestamp extends TimestampAction {
    private final long offsetSeconds;

    public OffsetTimestamp(long offsetSeconds) {
        this.offsetSeconds = offsetSeconds;
    }

    @Override
    public void execute(WSHandler handler, SecurityActionToken token, RequestData data)
            throws WSSecurityException {
        var builder = new WSSecTimestamp(data.getSecHeader());
        builder.setIdAllocator(data.getWssConfig().getIdAllocator());
        builder.setPrecisionInMilliSeconds(data.isPrecisionInMilliSeconds());
        builder.setTimeToLive(data.getTimeStampTTL());
        var source = data.getWssConfig().getCurrentTime();
        builder.setWsTimeSource(() -> source.now().plusSeconds(offsetSeconds));
        builder.setWsDocInfo(data.getWsDocInfo());
        builder.setExpandXopInclude(data.isExpandXopInclude());
        builder.build();
    }
}
