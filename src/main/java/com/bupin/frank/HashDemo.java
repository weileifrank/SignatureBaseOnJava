package com.bupin.frank;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.security.MessageDigest;

public class HashDemo {
    public static void main(String[] args) throws Exception {
        String input = "frank";
        String md5 = getDigest(input, "MD5");
        System.out.println("md5:"+md5);
        String sha1 = getDigest(input, "SHA-1");
        System.out.println("sha1:"+sha1);
        String sha256 = getDigest(input, "SHA-256");
        System.out.println("sha256:"+sha256);
        String sha512 = getDigest(input, "SHA-512");
        System.out.println("sha512:"+sha512);

        String fileSha1 = getDigestFile("a.txt", "SHA-1");
        System.out.println("fileSha1:"+fileSha1);

    }

    /**
     * 获取消息摘要
     *
     * @param input     : 原文
     * @param algorithm : 算法
     * @return : 消息摘要
     * @throws Exception
     */
    public static String getDigest(String input, String algorithm) throws Exception {
        // 获取MessageDigest对象
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        // 生成消息摘要
        byte[] digest = messageDigest.digest(input.getBytes());
        return toHex(digest);

    }

    /**
     *
     * @param filePath 文件路径
     * @param algorithm 算法
     * @return 返回对应的哈希值
     * @throws Exception
     */
    public static String getDigestFile(String filePath, String algorithm) throws Exception {
        FileInputStream fis = new FileInputStream(filePath);
        int len;
        byte[] buffer = new byte[1024];
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while ((len = fis.read(buffer)) != -1) {
            baos.write(buffer, 0, len);
        }
        // 获取MessageDigest对象
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        // 生成消息摘要
        byte[] digest = messageDigest.digest(baos.toByteArray());
        return toHex(digest);

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
