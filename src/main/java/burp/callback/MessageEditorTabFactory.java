package burp.callback;

import burp.*;
import burp.network.Transmission;

import java.awt.*;
import java.io.PrintStream;
import java.util.Arrays;

/**
 * @author user
 */
public class MessageEditorTabFactory implements IMessageEditorTabFactory {
    private final PrintStream stdout;
    private final PrintStream stderr;
    private final IBurpExtenderCallbacks callbacks;

    public MessageEditorTabFactory(PrintStream stdout, PrintStream stderr, IBurpExtenderCallbacks callbacks) {
        this.stdout = stdout;
        this.stderr = stderr;
        this.callbacks = callbacks;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new MessageEditorTab(stdout, stderr, callbacks.getHelpers(), callbacks.createTextEditor());
    }

    private static class MessageEditorTab implements IMessageEditorTab {
        private final PrintStream stdout;
        private final PrintStream stderr;
        private final ITextEditor editor;
        private final IExtensionHelpers helpers;
        private boolean isModified;

        public MessageEditorTab(PrintStream stdout, PrintStream stderr, IExtensionHelpers helpers, ITextEditor editor) {
            this.stdout = stdout;
            this.stderr = stderr;
            this.helpers = helpers;
            this.editor = editor;
            this.isModified = false;
        }

        @Override
        public String getTabCaption() {
            return BurpExtender.TAB_NAME;
        }

        @Override
        public Component getUiComponent() {
            return editor.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            if (isRequest) {
                IRequestInfo requestInfo = helpers.analyzeRequest(content);
                return Utils.isMatch(Utils.getUrl(requestInfo, content));
            }
            return true;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            byte[] text = content;
            try {
                if (isRequest) {
                    IRequestInfo requestInfo = helpers.analyzeRequest(content);
                    String url = Utils.getUrl(requestInfo, content);
                    if (Utils.isMatch(url)) {
                        stdout.printf("parse %s in editor\n", url);
                        text = Transmission.buildResponseBytes(helpers, Transmission.sendRequest(Bridge.getInstance().getUrl(),
                                0x800, url, requestInfo.getHeaders(), Arrays.copyOfRange(content,
                                        requestInfo.getBodyOffset(), content.length)));
                        isModified = true;
                    }
                } else {
                    IResponseInfo responseInfo = helpers.analyzeResponse(content);
                    text = Transmission.buildResponseBytes(helpers, Transmission.sendResponse(Bridge.getInstance().getUrl(),
                            0x800, null, responseInfo.getHeaders(), Arrays.copyOfRange(content,
                                    responseInfo.getBodyOffset(), content.length)));
                    isModified = true;
                }
            } catch (Exception e) {
                e.printStackTrace(stderr);
            }
            editor.setText(text);
        }

        @Override
        public byte[] getMessage() {
            return editor.getText();
        }

        @Override
        public boolean isModified() {
            return isModified;
        }

        @Override
        public byte[] getSelectedData() {
            return editor.getSelectedText();
        }
    }
}
