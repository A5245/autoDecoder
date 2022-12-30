package burp;

import org.json.JSONArray;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Vector;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * @author user
 */
public class Utils {
    private static final Pattern MATCH = Pattern.compile("HTTP/1.\\d");

    public static String b64encode(byte[] data) {
        return new String(Base64.getEncoder().encode(data));
    }

    public static byte[] b64decode(byte[] data) {
        return Base64.getDecoder().decode(data);
    }

    public static byte[] b64decode(String data) {
        return b64decode(data.getBytes(StandardCharsets.UTF_8));
    }

    public static boolean isEmpty(String value) {
        return value == null || value.isEmpty();
    }

    public static boolean isMatch(String url) {
        Bridge instance = Bridge.getInstance();
        TabShow show = instance.getShow();
        for (Vector<?> vector : show.getModel().getDataVector()) {
            Pattern compile = null;
            try {
                compile = Pattern.compile(vector.get(0).toString());
            } catch (PatternSyntaxException ignored) {
            }
            if (compile == null) {
                continue;
            }
            if (compile.matcher(url).find()) {
                return true;
            }
        }
        return false;
    }

    public static void inputText(String tips, Consumer<String> consumer) {
        String s = JOptionPane.showInputDialog(tips);
        if (Utils.isEmpty(s)) {
            return;
        }
        consumer.accept(s);
    }

    public static List<String> jsonArrayToList(JSONArray array) {
        List<String> result = new ArrayList<>(array.length());
        for (Object o : array) {
            result.add(o.toString());
        }
        return result;
    }

    public static String getUrlByBytes(byte[] data) {
        String[] split = new String(data).split("\n");
        String urlPath = null;
        String host = null;
        for (String each : split) {
            if (urlPath != null && host != null) {
                break;
            }
            if (MATCH.matcher(each).find()) {
                urlPath = each.split(" ")[1];
            } else if (each.toLowerCase().startsWith("host:")) {
                host = each.substring(5).trim();
            }
        }
        return host + urlPath;
    }

    public static String getUrl(IRequestInfo info, byte[] data) {
        String url;
        try {
            url = info.getUrl().toString();
        } catch (UnsupportedOperationException ignored) {
            url = Utils.getUrlByBytes(data);
        }
        return url;
    }
}
