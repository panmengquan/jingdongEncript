package example;

import com.alibaba.fastjson.JSONObject;

public class EncryptQuestParams {
    private String type;
    private JSONObject data;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public JSONObject getData() {
        return data;
    }

    public void setData(JSONObject data) {
        this.data = data;
    }
}
