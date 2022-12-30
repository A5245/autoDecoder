package burp.network;

import okhttp3.*;

/**
 * @author user
 */
public class Network {
    private static final MediaType JSON
            = MediaType.parse("application/json; charset=utf-8");
    private static final OkHttpClient OK_HTTP_CLIENT = new OkHttpClient();

    public static String post(Request request) {
        try (Response execute = OK_HTTP_CLIENT.newCall(request).execute()) {
            try (ResponseBody responseBody = execute.body()) {
                return responseBody.string();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Request newRequest(String url, Transmission.Packet body) {
        return new Request.Builder().url(url).post(RequestBody.create(body.toString(), JSON)).build();
    }
}
