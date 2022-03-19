package wiki.zimo.wiseduunifiedloginapi.utils;


import com.alibaba.fastjson.JSONObject;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.HashMap;
import java.util.Map;

/**
 * 集成 proxy_pool 代理池，封装 jsoup
 * todo 在 CasLoginProcess 中写 getProxy() ，catch到异常再去重复获取代理ip
 */
public class MyConnection {

    private static String PROXY_API = "http://127.0.0.1:5010/get";

    /**
     * 获取代理
     * @return
     * @throws Exception
     */
    private static HashMap<String, String> getProxy() throws Exception {
        // 最多尝试获取代理计数器
        int proxyAvailableCount = 10;
        // 代理ip
        String ip = "";
        // 代理端口
        String port = "";
        while (proxyAvailableCount > 0){
            try {
                Connection proxy = Jsoup.connect(PROXY_API)
                        .ignoreContentType(true)
                        .header("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1")
                        .followRedirects(true);
                Connection.Response proxyResponse = proxy.execute();
                Document proxyDoc = proxyResponse.parse();
                Element proxyElement = proxyDoc.getElementsByTag("body").first();
                JSONObject proxyIp = JSONObject.parseObject(proxyElement.text());
                if ("true".equals(proxyIp.get("https").toString())) {
                    String res = proxyIp.get("proxy").toString();
                    String[] resList = res.split(":");
                    ip = resList[0];
                    port = resList[1];
                    break;
                }
            } catch (Exception ignored) {
                proxyAvailableCount = proxyAvailableCount -1;
            }
        }
        HashMap<String, String> res = new HashMap<>();
        if (!ip.equals("") && !port.equals("")){
            res.put("ip", ip);
            res.put("port", port);
            return res;
        }
        throw new Exception("代理获取失败，检查proxy_pool");
    }



    public static Connection myJsoup(String url, Map<String, String> headerMap, Map<String, String> cookiesMap) throws Exception{

        HashMap<String, String> proxyMap = getProxy();
        System.out.println(proxyMap.get("ip") + ":" + proxyMap.get("port"));
        return Jsoup.connect(url)
                .headers(headerMap)
                .cookies(cookiesMap)
                //.proxy(proxyMap.get("ip"), Integer.parseInt(proxyMap.get("port")))
                .ignoreContentType(true)
                .followRedirects(true);
    }

    public static Connection myJsoup(String url, String headerKey, String headerVal) throws Exception {

        HashMap<String, String> proxyMap = getProxy();
        System.out.println(proxyMap.get("ip") + ":" + proxyMap.get("port"));
        return Jsoup.connect(url)
                .header(headerKey, headerVal)
                //.proxy(proxyMap.get("ip"), Integer.parseInt(proxyMap.get("port")))
                .followRedirects(true)
                .ignoreContentType(true);
    }

    public static Connection myJsoup(String url, String headerKey, String headerVal, Map<String, String> cookiesMap, Connection.Method method) throws Exception {

        HashMap<String, String> proxyMap = getProxy();
        System.out.println(proxyMap.get("ip") + ":" + proxyMap.get("port"));
        return Jsoup.connect(url)
                .header(headerKey, headerVal)
                .cookies(cookiesMap)
                .method(method)
                //.proxy(proxyMap.get("ip"), Integer.parseInt(proxyMap.get("port")))
                .followRedirects(true)
                .ignoreContentType(true);
    }

    public static Connection myJsoup(String url) throws Exception {

        HashMap<String, String> proxyMap = getProxy();
        System.out.println(proxyMap.get("ip") + ":" + proxyMap.get("port"));
        return Jsoup.connect(url);
                //.proxy(proxyMap.get("ip"), Integer.parseInt(proxyMap.get("port")));
    }

}
