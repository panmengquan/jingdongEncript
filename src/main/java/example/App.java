package example;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.util.Set;
import java.util.stream.Collectors;
import javax.servlet.ServletException;

import com.alibaba.fastjson.JSONObject;
import com.aliyun.fc.runtime.Context;
import com.aliyun.fc.runtime.FunctionInitializer;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.aliyun.fc.runtime.HttpRequestHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;

/**
 * Hello world!
 *
 */
public class App implements HttpRequestHandler, FunctionInitializer {

    public void initialize(Context context) throws IOException {
        //TODO
    }

    @Override
    public void handleRequest(HttpServletRequest request, HttpServletResponse response, Context context)
            throws IOException, ServletException {
        String requestPath = (String) request.getAttribute("FC_REQUEST_PATH");
        String requestURI = (String) request.getAttribute("FC_REQUEST_URI");
        String requestClientIP = (String) request.getAttribute("FC_REQUEST_CLIENT_IP");

        String requestParms = "";
        SimpleResponse simpleResponse = new SimpleResponse();

        try {
            if ("POST".equalsIgnoreCase(request.getMethod())) {
                requestParms = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));
                if (requestParms.isEmpty()) return;

                simpleResponse.setCode(200);
                simpleResponse.setMessage("请求成功");

                ObjectMapper objectMapper = new ObjectMapper();

                JSONObject responseObject = new JSONObject();
                EncryptQuestParams paramsBeanCopy = objectMapper.readValue(requestParms, EncryptQuestParams.class);

                EncryptQuestParams paramsBean = objectMapper.readValue(requestParms, EncryptQuestParams.class);

                JSONObject oldObject = paramsBean.getData();
                Set<String> keys = oldObject.keySet();
                for (String key : keys) {
                    String oldValue = (String) oldObject.get(key); // 获取对应的值
                    if (oldValue.contains("https")) {
                        oldValue = URLEncoder.encode(oldValue, "UTF-8");
                    }
                    String newValue = "";
                    if (paramsBean.getType().equals("加密")) {
                        newValue = CommonUtils.encryptParam(oldValue, CommonUtils.rsaEncryptPublicKey);
                    } else {
                        newValue = CommonUtils.decryptParam(oldValue, CommonUtils.rsaSignPrivateKey);
                    }
                    oldObject.put(key, newValue);
                }
                responseObject.put("data", oldObject);
                if (paramsBean.getType().equals("加密")) responseObject.put("sign", CommonUtils.getMySign(paramsBeanCopy.getData()));

                if (paramsBean.getType().equals("加密")){
                    JSONObject copyObj = (JSONObject) oldObject.clone();
                    copyObj.put("sign", CommonUtils.getMySign(paramsBeanCopy.getData()));
                    responseObject.put("url", pintJsonObject(copyObj));
                }
                simpleResponse.setData(responseObject);
                OutputStream out = response.getOutputStream();
                out.write((new Gson().toJson(simpleResponse)).getBytes());
                out.flush();
                out.close();

            }

        } catch (Exception e) {
            simpleResponse.setMessage(e.toString());
            OutputStream out = response.getOutputStream();
            out.write((new Gson().toJson(simpleResponse)).getBytes());
            out.flush();
            out.close();
        }
    }
    public static String pintJsonObject(JSONObject object){
        String dominalUrl = "https://jxi-fuli-login.jd.com/autoLogin?appTarget=5&loginCode="+CommonUtils.accessKey;
        StringBuilder sb = new StringBuilder();
        Set<String> keys = object.keySet();
        for (String key : keys) {
            String oldValue = (String) object.get(key); // 获取对应的值
            sb.append( key+ "=" + CommonUtils.replaceBlank(oldValue.trim()) + "&");
        }
        String url = dominalUrl+"&"+sb.toString();
        url = url.replaceAll("\\+", "%2B");
        System.out.println("pintJsonObject: " + url);
        return url;
    }
}
