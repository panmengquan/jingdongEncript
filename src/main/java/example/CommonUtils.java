package example;

import com.alibaba.fastjson.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CommonUtils {
    public static final int MAX_DECRYPT_BLOCK = 128;
    public static final int MAX_ENCRYPT_BLOCK = 117;
    public static final String KEY_ALGORITHM_DETAIL = "RSA/ECB/PKCS1Padding";

    public final static String rsaSignPrivateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIUNkeBqbKxKtxO37UV2MR/DfC32UCAvNmFHajuALL7DcNLYInbrlAK3i1pPnwGdlwD4n4urNMJcemiZmO5xoygF7nXeQkG3OfrVPB6qmv8KO3nsG40PvN0XVBu04DQgWkjIyvpsnVnVhuw+K/k3RAGr7Swo2z7OXt0+kfREumGnAgMBAAECgYAmVYyL/d2lnjk1Iy7nbnAk2Ku0ilz3iOLAEFVZI0rBA4pEFSWI4cLZLYymzn3fd0oEa518Hi2rOf3CmU5olLEO8j/hROfv2EKIU+mARjeqWB0hdaqYMcl2d2xCzblIgF2qEkdMLlDFC3Jd2BsqQ9tmyXUq6jUfC++HSILH3hTJsQJBAMiAYlUhBFpc3XJhAmEOx7B5xPCp/nZuQZEXILC7E4C/RLyBKimNdjt3S6tmwaTMujT8BCrWDR2GzGQX0cUaGaMCQQCp4cI7X2D9fhDoKMtuj8LBe0sHsv1AzkrQ2deaa2Gf7b13Z3jRn7hEkq/3+tjXx0MPaiRJL0mzd2iga93iSqAtAkBjNxRxp6rtxDJYnSR+PsAV1cvcg2JF3H1ZfKZSjeAyv3MWDJx+f1/YQUoSgQCluiESgvrU76MBz2hox1ioPigdAkApC/ZdWCdcOIinP6wfs7av/zVaz+GnNfEX03rnwchd1xivcB3eMIRadUL1XPPl9yx53gCUekuJhHGQSV/cXIGlAkB/ufzJN0dc+YXzGM95G+vuGRHFlyHIaSn/pPdXjbn+AYmsW8LV8ZQLK2qNPN2rGKJ+u0SfTOp/5YKwoEvRAZPY";
    public final static String rsaEncryptPublicKey ="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDb88/7V2YYEcIaWvol8MpxwXLXjmdU6YgIXwc7qjz8j5p8aGwALlU9qvIAUzFWPIaj3S05TUhPn/TQhIVllktphmF2Q0pS4IV/U9ZF5v6TlYUCW+n4isZKdSWm9JYDnJo4b9n/xH+GDoKR7AL2jjrSgamf709HVMvNHzbri8NvmQIDAQAB";
    public final static String accessKey = "8lkNvadfU1-a9RYFsgiioTL3Q1ck5VlFuNcap--_NWo=";

    public static String getMySign(JSONObject params) throws Exception{
        //sign验证
        List<String> unsignedKeyList = new ArrayList<>();
        unsignedKeyList.add("version");
        unsignedKeyList.add("sign");
        // 获取验签sign
        // 1.将参数按照ASCII码从小到大的顺序排列并使用&符号拼接-s1
        String s1 = signMyString(params, unsignedKeyList);
        // 2.将s1使用"SHA-256"加密方式进行加密获取字符串-s2
        String s2 = encrypt(s1, "SHA-256");
        // 3.将s2再使用验签私钥进行加密成为s3
        byte[] s2Rsa = encryptByPrivateKey(s2.getBytes("UTF-8"), rsaSignPrivateKey);
        // 4.将s3进行base64进行编码
        String sign = encryptBASE64(s2Rsa);
        return sign;
    }
    /**
     * 参数加密
     *
     * @param srcStr 要加密的原始字符串
     * @param rsaEncryptPubKey 加密RSA公钥
     * @return
     */
    public static String encryptParam(String srcStr, String rsaEncryptPubKey) {
        try {
            byte[] s1Byte = encryptByPublicKey(srcStr.getBytes(),rsaEncryptPubKey);
            String s1 = encryptBASE64(s1Byte);
            return s1;
        } catch (Exception e) {
            System.out.println("参数加密失败,srcStr=" + srcStr);
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 参数解密
     * @param encryptedStr 已加密的字符串
     * @param rsaSignPrivKey 加密RSA私钥
     * @return
     */
    public static String decryptParam(String encryptedStr, String rsaSignPrivKey) {
        try {
            byte[] s1EncryptedByte = decryptBASE64(encryptedStr);
            byte[] s1Byte = decryptByPrivateKey(s1EncryptedByte, rsaSignPrivKey);
            return new String(s1Byte);
        } catch (Exception e) {
            System.out.println("参数解密失败,encryptedStr=" + encryptedStr);
            e.printStackTrace();
            return null;
        }
    }

    public static String signMyString(JSONObject object, List<String> unSignKeyList) throws IllegalArgumentException, IllegalAccessException {
        TreeMap map = jsonObjectToTreeMap(object);
        return genSrcData(map, unSignKeyList);
    }

    public static TreeMap<String, Object> jsonObjectToTreeMap(JSONObject jsonObject) {
        TreeMap<String, Object> treeMap = new TreeMap<>();

        // 获取所有键的集合
        Set<String> keys = jsonObject.keySet();
        for (String key : keys) {
            // 将键值对添加到 TreeMap 中
            treeMap.put(key, jsonObject.get(key));
        }

        return treeMap;
    }
    public static String genSrcData(TreeMap<String, Object> paramMap, List<String> unSignKeyList) {
        StringBuilder sb = new StringBuilder();
        Iterator result = unSignKeyList.iterator();

        while (result.hasNext()) {
            String iterator = (String) result.next();
            paramMap.remove(iterator);
        }

        Iterator iterator1 = paramMap.entrySet().iterator();

        while (iterator1.hasNext()) {
            Map.Entry result1 = (Map.Entry) iterator1.next();
            if (result1.getValue() != null  && ((String) result1.getValue()).trim().length() > 0) {
                sb.append(result1.getKey() + "=" + result1.getValue() + "&");
            }
        }

        String result2 = sb.toString();
        if (result2.endsWith("&")) {
            result2 = result2.substring(0, result2.length() - 1);
        }
        return result2;
    }

    public static String encrypt(String strSrc, String encName) {
        MessageDigest md = null;
        String strDes = null;
        byte[] bt = new byte[0];

        try {
            bt = strSrc.getBytes("UTF-8");
        } catch (UnsupportedEncodingException var6) {
            return null;
        }

        try {
            if(encName == null || encName.equals("")) {
                encName = "SHA-256";
            }

            md = MessageDigest.getInstance(encName);
            md.update(bt);
            strDes = bytes2Hex(md.digest());
            return strDes;
        } catch (NoSuchAlgorithmException var7) {
            return null;
        }
    }

    public static String bytes2Hex(byte[] bts) {
        String des = "";
        String tmp = null;

        for(int i = 0; i < bts.length; ++i) {
            tmp = Integer.toHexString(bts[i] & 255);
            if(tmp.length() == 1) {
                des = des + "0";
            }

            des = des + tmp;
        }

        return des;
    }

    public static byte[] encryptByPrivateKey(byte[] data, String key) throws Exception {
        byte[] keyBytes = decryptBASE64(key);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        return doFinalSplit(data, privateKey, Cipher.ENCRYPT_MODE);
    }

    public static byte[] decryptBASE64(String key) throws Exception {
        return Base64.getDecoder().decode(key);
//        return (new BASE64Decoder()).decodeBuffer(key);
    }

    public static String encryptBASE64(byte[] key) throws Exception {
        return Base64.getEncoder().encodeToString(key);
//        return (new BASE64Encoder()).encodeBuffer(key);
    }

    private static byte[] doFinalSplit(byte[] b, Key key, int mode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        int inputLen = b.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM_DETAIL);
        cipher.init(mode, key);


        Integer lenth ;
        if (Cipher.ENCRYPT_MODE == mode){
            lenth = MAX_ENCRYPT_BLOCK;
        }else if(Cipher.DECRYPT_MODE == mode){
            lenth = MAX_DECRYPT_BLOCK;
        }else {
            throw new RuntimeException("error Cipher mode");
        }
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > lenth) {
                cache = cipher.doFinal(b, offSet, lenth);
            } else {
                cache = cipher.doFinal(b, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * lenth;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /**
     * @param key
     * @param key
     * @return String
     * @Title: RSADecode
     * @Description: 将字符串解密
     */
    public static byte[] decryptByPrivateKey(byte[] b, String key) throws Exception {

        byte[] keyBytes = decryptBASE64(key);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        return doFinalSplit(b, privateKey,Cipher.DECRYPT_MODE);
    }

    /**
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String key) throws Exception {
        byte[] keyBytes = decryptBASE64(key);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);

        return doFinalSplit(data, publicKey,Cipher.ENCRYPT_MODE);
    }
    public static String replaceBlank(String str) {
        String dest = "";
        if (str!=null) {
            Pattern p = Pattern.compile("\\s*|\t|\r|");
            Matcher m = p.matcher(str);
            dest = m.replaceAll("");
        }
        return dest;
    }



}
