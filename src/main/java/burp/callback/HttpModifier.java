package burp.callback;

import burp.*;
import burp.network.Transmission;

import java.io.PrintStream;
import java.util.Arrays;

/**
 * @author user
 */
public class HttpModifier implements IHttpListener {
    private final PrintStream stdout;
    private final PrintStream stderr;
    private final IExtensionHelpers helpers;

    public HttpModifier(PrintStream stdout, PrintStream stderr, IBurpExtenderCallbacks callbacks) {
        this.stdout = stdout;
        this.stderr = stderr;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag != IBurpExtenderCallbacks.TOOL_REPEATER && toolFlag != IBurpExtenderCallbacks.TOOL_INTRUDER
                && toolFlag != IBurpExtenderCallbacks.TOOL_PROXY && toolFlag != IBurpExtenderCallbacks.TOOL_EXTENDER) {
            return;
        }

        byte[] back = messageIsRequest ? messageInfo.getRequest() : messageInfo.getResponse();
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);

        String url = Bridge.getInstance().getUrl();

        try {
            String targetUrl = requestInfo.getUrl().toString();
            if (Utils.isMatch(targetUrl)) {
                stdout.printf("Match url %s\n", targetUrl);
                if (messageIsRequest) {
                    back = Transmission.buildResponse(helpers, url, Transmission.newPacket(Transmission.Packet.Type.REQUEST, toolFlag,
                            targetUrl, requestInfo.getHeaders(), Arrays.copyOfRange(back, requestInfo.getBodyOffset(), back.length)));
                } else {
                    IResponseInfo responseInfo = helpers.analyzeResponse(back);
                    back = Transmission.buildResponse(helpers, url, Transmission.newPacket(Transmission.Packet.Type.RESPONSE, toolFlag,
                            targetUrl, responseInfo.getHeaders(), Arrays.copyOfRange(back, responseInfo.getBodyOffset(), back.length)));
                }
            }
        } catch (Exception e) {
            e.printStackTrace(stderr);
        }

        if (messageIsRequest) {
            messageInfo.setRequest(back);
        } else {
            messageInfo.setResponse(back);
        }
    }
}
