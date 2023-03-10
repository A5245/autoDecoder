package burp.network;

import burp.Bridge;
import burp.IExtensionHelpers;
import burp.Utils;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * @author user
 */
public class Transmission {
    public static String send(String url, Packet packet) {
        return Network.post(Network.newRequest(url, packet));
    }

    public static Packet newPacket(Packet.Type type, int from, String targetUrl, List<String> headers, byte[] body) {
        return new Packet(from, type, targetUrl, headers, body);
    }

    public static byte[] buildResponse(IExtensionHelpers helpers, String url, Packet packet) {
        JSONObject jsonObject = new JSONObject(send(url, packet));
        byte[] body = Utils.b64decode(jsonObject.getString(Packet.BODY));
        List<String> headersString;
        if (jsonObject.has(Packet.HEADERS) && jsonObject.has(Packet.ORDER)) {
            JSONObject headers = jsonObject.getJSONObject(Packet.HEADERS);
            headersString = new ArrayList<>(headers.length());
            for (Object each : jsonObject.getJSONArray(Packet.ORDER)) {
                String name = each.toString();
                if ("main".equals(name)) {
                    headersString.add(headers.getString(name));
                    continue;
                }
                headersString.add(String.format("%s: %s", name, headers.getString(name)));
            }
        } else {
            headersString = packet.headers;
        }
        return helpers.buildHttpMessage(headersString, body);
    }

    public static class Packet {
        public static final String ORDER = "order";
        public static final String FROM = "from";
        public static final String TYPE = "type";
        public static final String HEADERS = "headers";
        public static final String URL = "url";
        public static final String BODY = "body";
        public static final String FLAG = "flag";
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

            JSONObject headers = new JSONObject();
            headers.put("main", this.headers.get(0));
            JSONArray order = new JSONArray(Collections.singleton("main"));
            for (String each : this.headers.subList(1, this.headers.size())) {
                int splitPoint = each.indexOf(":");
                String name = each.substring(0, splitPoint).trim();
                String value = each.substring(splitPoint + 1).trim();
                order.put(name);
                headers.put(name, value);
            }
            jsonObject.put(FLAG, Bridge.getInstance().getFlag());
            jsonObject.put(ORDER, order);
            jsonObject.put(HEADERS, headers);
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
