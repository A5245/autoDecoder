package burp;

import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.io.File;
import java.io.PrintStream;

/**
 * @author user
 */
public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab {
    public static final String TAB_NAME = "autoDecoder-Beta";
    private static final String PROFILE_NAME = "autoDecoder-Beta.json";
    private TabShow show;

    public static File getPath(IBurpExtenderCallbacks callbacks) {
        String oss = System.getProperty("os.name");
        if (oss.toLowerCase().startsWith("win")) {
            return new File(PROFILE_NAME);
        }
        String jarPath = callbacks.getExtensionFilename();
        return new File(jarPath.substring(0, jarPath.lastIndexOf("/")), PROFILE_NAME);
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        Bridge instance = Bridge.getInstance();
        instance.setProfile(getPath(callbacks));
        show = instance.getShow();
        show.addData(instance.readRules());
        show.setUrl(instance.getUrl());
        PrintStream stdout = new PrintStream(callbacks.getStdout());
        PrintStream stderr = new PrintStream(callbacks.getStderr());

        callbacks.addSuiteTab(this);
        callbacks.registerHttpListener(new HttpModifier(stdout, stderr, callbacks));
        callbacks.registerMessageEditorTabFactory(new MessageEditorTabFactory(stdout, stderr, callbacks));
    }

    @Override
    public String getTabCaption() {
        return TAB_NAME;
    }

    @Override
    public Component getUiComponent() {
        return show.$$$getRootComponent$$$();
    }

    @Override
    public int getRowCount() {
        return 0;
    }

    @Override
    public int getColumnCount() {
        return 0;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        return null;
    }
}
