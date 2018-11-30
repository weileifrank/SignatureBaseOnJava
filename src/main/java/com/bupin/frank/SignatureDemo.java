package com.bupin.frank;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SignatureDemo {
    public static void main(String[] args) throws Exception {
        String algorithm = "RSA";
        String priPath = "test.pri";
        String pubPath = "test.pub";
        String input = "frank";
//        RSAUtil.generateKeys(algorithm,priPath,pubPath);

        PrivateKey privateKey = RSAUtil.getPrivateKey(priPath, algorithm);
        PublicKey publicKey = RSAUtil.getPublicKey(pubPath, algorithm);

        String signatureAlgorithm = "SHA256withRSA";
        String signatured = getSignature(input, privateKey, signatureAlgorithm);

        boolean verify = verifySignature(input, publicKey, signatureAlgorithm, signatured);
        System.out.println(verify);
    }

    /**
     * 生成签名字符串
     * @param input  原文
     * @param privateKey 私钥
     * @param signatureAlgorithm 签名算法
     * @return
     * @throws Exception
     */
    public static String getSignature(String input, PrivateKey privateKey, String signatureAlgorithm) throws Exception {
        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(privateKey);
        signature.update(input.getBytes());
        byte[] sign = signature.sign();
        return Base64.encode(sign);
    }

    /**
     * 校验签名
     * @param input 原文
     * @param publicKey 公钥
     * @param signatureAlgorithm 签名算法
     * @param signatured 发送过来的签名
     * @return
     * @throws Exception
     */
    public static boolean verifySignature(String input, PublicKey publicKey, String signatureAlgorithm, String signatured) throws Exception {
        Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initVerify(publicKey);
        signature.update(input.getBytes());
        return signature.verify(Base64.decode(signatured));

    }
}
