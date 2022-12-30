import burp.TabShow;

import javax.swing.*;

/**
 * @author user
 */
public class UITest {
    public static void main(String[] args) {
        JFrame frame = new JFrame();
        TabShow tabShow = new TabShow();
        tabShow.addData("ASD");
        frame.setContentPane(tabShow.$$$getRootComponent$$$());
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.pack();
        frame.setVisible(true);
    }
}
