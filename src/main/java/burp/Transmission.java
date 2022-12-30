package burp;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/**
 * @author user
 */
public class Transmission {
    public static String send(String url, Packet packet) {
        return Network.post(Network.newRequest(url, packet));
    }

    public static String sendRequest(String url, int from, String targetUrl, List<String> headers, byte[] body) {
        return send(url, new Packet(from, Packet.Type.REQUEST, targetUrl, headers, body));
    }

    public static String sendResponse(String url, int from, String targetUrl, List<String> headers, byte[] body) {
        return send(url, new Packet(from, Packet.Type.RESPONSE, targetUrl, headers, body));
    }

    public static byte[] buildResponseBytes(IExtensionHelpers helpers, String data) {
        JSONObject jsonObject = new JSONObject(data);
        byte[] body = Utils.b64decode(jsonObject.getString(Packet.BODY));
        if (jsonObject.has(Packet.HEADERS)) {
            return helpers.buildHttpMessage(Utils.jsonArrayToList(jsonObject.getJSONArray(Packet.HEADERS)), body);
        }
        return body;
    }

    public static class Packet {
        public static final String FROM = "from";
        public static final String TYPE = "type";
        public static final String HEADERS = "headers";
        public static final String URL = "url";
        public static final String BODY = "body";
        private final int from;
        private final Type type;
        private final String url;
        private final List<String> headers;
        private final byte[] body;

        public Packet(int from, Type type, String url, List<String> headers, byte[] body) {
            this.from = from;
            this.type = type;
            this.url = url;
            this.headers = headers;
            this.body = body;
        }


        @Override
        public String toString() {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put(FROM, from);
            jsonObject.put(TYPE, type.ordinal());
            jsonObject.put(HEADERS, new JSONArray().putAll(headers));
            jsonObject.put(URL, url);
            jsonObject.put(BODY, Utils.b64encode(body));
            return jsonObject.toString();
        }

        public enum Type {
            REQUEST,
            RESPONSE
        }
    }
}
