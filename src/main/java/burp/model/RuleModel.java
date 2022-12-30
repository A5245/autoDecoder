package burp.model;

import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.table.DefaultTableModel;
import java.util.Vector;

/**
 * @author user
 */
public class RuleModel extends DefaultTableModel {
    public RuleModel() {
        super(null, new String[]{"Rule"});
    }

    public void add(String data) {
        addRow(new String[]{data});
    }

    public JSONObject getValue() {
        JSONObject result = new JSONObject();

        JSONArray objects = new JSONArray();
        for (Vector<?> vector : getDataVector()) {
            objects.put(vector.get(0));
        }
        result.put("rules", objects);
        return result;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return false;
    }
}
