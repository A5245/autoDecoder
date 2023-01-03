package burp;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
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

    /**
     * 匹配URL是否满足Rules规则
     *
     * @param url 目标URL地址
     * @return 是否匹配Rules
     */
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

    /**
     * 弹窗获取用户输入
     *
     * @param tips     输入框提示
     * @param consumer 输入字符串处理
     */
    public static void inputText(String tips, Consumer<String> consumer) {
        String s = JOptionPane.showInputDialog(tips);
        if (Utils.isEmpty(s)) {
            return;
        }
        consumer.accept(s);
    }

    /**
     * 通过数据包Header头获取URL地址（Editor中无法使用analyzeRequest获取URL）
     * 无法获取协议类型（例如：https/http）
     *
     * @param data 数据包
     * @return 当前数据包中的URL
     */
    public static String getUrlByBytes(byte[] data) {
        String[] split = new String(data).split("\n");
        String urlPath = null;
        String host = "";
        for (String each : split) {
            if (urlPath != null && isEmpty(host)) {
                break;
            }
            if (MATCH.matcher(each).find()) {
                urlPath = each.split(" ")[1];
                if (urlPath.startsWith("http")) {
                    break;
                }
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
