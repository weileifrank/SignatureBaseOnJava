package com.bupin.frank;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MacDemo {
    public static void main(String[] args) throws Exception {
        String input = "frank";
        String keyString = "123DLLFLH";
        String algorithm = "HmacSHA256";

        String hmac = generateHmac(input, keyString, algorithm);
        System.out.println(hmac);
        boolean b = verifyHamc("frank", keyString, algorithm, hmac);
        System.out.println(b);
    }

    /**
     *
     * @param input 原文
     * @param keyString 秘钥
     * @param algorithm 算法
     * @return 返回的消息认证码
     * @throws Exception
     */
   public static String generateHmac(String input,String keyString,String algorithm) throws Exception {
       Mac mac = Mac.getInstance(algorithm);
       Key key = new SecretKeySpec(keyString.getBytes(), "");
       mac.init(key);
       byte[] result = mac.doFinal(input.getBytes());
       String hmac = toHex(result);
       return hmac;
   }

    /**
     * 消息认证
     * @param input 原文
     * @param keyString 秘钥序列
     * @param algorithm 算法
     * @param hmac 传入的消息认证码
     * @return
     * @throws Exception
     */
    public static boolean verifyHamc(String input,String keyString,String algorithm,String hmac) throws Exception {
        String newHmac = generateHmac(input, keyString, algorithm);
        if (newHmac != null && newHmac.equals(hmac)) {
            return true;
        }
        return false;
    }

    // 将字节数组转为16进制字符串
    public static String toHex(byte[] digest) {
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            int i = b & 0xff;
            String s = Integer.toHexString(i);
            if (s.length() == 1) {
                s = "0" + s;
            }
            sb.append(s);
        }
        return sb.toString();
    }
}
