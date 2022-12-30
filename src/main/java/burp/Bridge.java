package burp;

import burp.model.RuleModel;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * @author user
 */
public class Bridge {
    public static final String URL = "url";
    public static final String RULES = "rules";
    private static File profile;
    private static Bridge instance;
    private final TabShow show;
    private String url;

    private Bridge() {
        show = new TabShow();
    }

    public static Bridge getInstance() {
        synchronized (Bridge.class) {
            if (instance == null) {
                instance = new Bridge();
            }
        }
        return instance;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public void setProfile(File file) {
        synchronized (Bridge.class) {
            profile = file;
        }
    }

    public List<String> readRules() {
        List<String> result = new ArrayList<>();
        try (FileInputStream fileInputStream = new FileInputStream(profile)) {
            JSONObject objects = new JSONObject(new String(fileInputStream.readAllBytes()));
            if (!objects.has(RULES)) {
                return result;
            }
            JSONArray rules = objects.getJSONArray(RULES);
            for (int i = 0; i < rules.length(); i++) {
                result.add(rules.getString(i));
            }
            if (objects.has(URL)) {
                url = objects.getString(URL);
            }
        } catch (FileNotFoundException ignored) {
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public void saveModel(RuleModel ruleModel) {
        if (profile == null) {
            return;
        }
        if (!profile.exists()) {
            try {
                if (!profile.createNewFile()) {
                    throw new IllegalStateException();
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        try (FileOutputStream fileInputStream = new FileOutputStream(profile)) {
            JSONObject value = ruleModel.getValue();
            value.put(URL, url);
            fileInputStream.write(value.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public TabShow getShow() {
        return show;
    }
}
