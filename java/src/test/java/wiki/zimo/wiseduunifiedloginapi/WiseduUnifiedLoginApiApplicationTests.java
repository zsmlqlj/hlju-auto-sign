package wiki.zimo.wiseduunifiedloginapi;

import com.alibaba.fastjson.JSONObject;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.util.HashMap;



@SpringBootTest
class WiseduUnifiedLoginApiApplicationTests {

//    private String PROXY_API = "http://127.0.0.1:5010/get/";
//
//    @Test
//    void proxyTest() throws Exception {
//        // 最多尝试获取代理计数器
//        int proxyAvailableCount = 6;
//        // 代理ip
//        String ip = "";
//        // 代理端口
//        String port = "";
//        while (proxyAvailableCount > 0){
//            try {
//                Connection proxy = Jsoup.connect(PROXY_API)
//                        .ignoreContentType(true)
//                        .header("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1")
//                        .followRedirects(true);
//                Connection.Response proxyResponse = proxy.execute();
//                Document proxyDoc = proxyResponse.parse();
//                Element proxyElement = proxyDoc.getElementsByTag("body").first();
//                JSONObject proxyIp = JSONObject.parseObject(proxyElement.text());
//                if ("true".equals(proxyIp.get("https").toString())) {
//                    String res = proxyIp.get("proxy").toString();
//                    String[] resList = res.split(":");
//                    ip = resList[0];
//                    port = resList[1];
//                    break;
//                }
//            } catch (Exception ignored) {
//                proxyAvailableCount = proxyAvailableCount -1;
//            }
//        }
//        HashMap<String, String> res = new HashMap<>();
//        if (!ip.equals("") && !port.equals("")){
//            res.put("ip", ip);
//            res.put("port", port);
//        }
//        System.out.println(res.get("ip"));
//        System.out.println(res.get("port"));
////        throw new Exception("代理获取失败，检查proxy_pool");
//
//    }

//    @Test
//    void test() throws IOException {
//        // 获取代理并启用
//        Connection proxy = Jsoup.connect(PROXY_API)
//                .ignoreContentType(true)
//                .postDataCharset("utf-8")
//                .header("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1")
//                .followRedirects(true);
//        Connection.Response proxyResponse = proxy.execute();
//        System.out.println(proxyResponse);
//        Document proxyDoc = proxyResponse.parse();
//        System.out.println(proxyDoc);
//        Element proxyElement = proxyDoc.getElementsByTag("body").first();
//        System.out.println(proxyElement);
//        JSONObject proxyIp = JSONObject.parseObject(proxyElement.text());
//        String res = proxyIp.get("proxy").toString();
//        System.out.println(res);
//    }

}
