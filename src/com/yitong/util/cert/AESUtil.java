package com.yitong.util.cert;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

/**
 * @author chengqg
 * 
 */
public class AESUtil {
	
    public static String encryptWithBC(String data, String key) throws Exception {
//    	System.out.println("--------------业务数据加密开始--------------");
//    	System.out.println("加密前字符串=[" + data + "]");
        ByteBuffer buffer = ByteBuffer.allocate(32);
        buffer.put(key.getBytes());
        KeyParameter kp = new KeyParameter(buffer.array());
        byte[] bytes = data.getBytes("UTF8");

        CBCBlockCipher aes = new CBCBlockCipher(new AESEngine());
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(aes, new PKCS7Padding());
        cipher.init(true, kp);

        byte[] output = new byte[cipher.getOutputSize(bytes.length)];
        int len = cipher.processBytes(bytes, 0, bytes.length, output, 0);
        cipher.doFinal(output, len);
        String encryptStr = Base64.encodeBase64String(output);
//      System.out.println("加密后字符串=[" + encryptStr + "]");
//      System.out.println("--------------业务数据加密结束--------------");
        return encryptStr;
    }

    public static String decryptWithBC(String data, String key) throws Exception {
//    	System.out.println("--------------业务数据解密开始--------------");
//    	System.out.println("解密前字符串=[" + data + "]");
        ByteBuffer buffer = ByteBuffer.allocate(32);
        buffer.put(key.getBytes());
        KeyParameter kp = new KeyParameter(buffer.array());

        byte[] bytes = Base64.decodeBase64(data);

        CBCBlockCipher aes = new CBCBlockCipher(new AESEngine());
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(aes, new PKCS7Padding());
        cipher.init(false, kp);

        byte[] output = new byte[cipher.getOutputSize(bytes.length)];
        int len = cipher.processBytes(bytes, 0, bytes.length, output, 0);
        int len2 = cipher.doFinal(output, len);
        byte rawData[] = new byte[len+len2];
        System.arraycopy(output, 0, rawData, 0, rawData.length);
        String plainData = new String(rawData, Charset.forName("utf-8"));
//      System.out.println("解密后字符串=[" + plainData + "]");
//      System.out.println("--------------业务数据解密结束--------------");
        return plainData;
    }

    /**
     * 生成随机密钥，一次一密
     * @return
     */
    public static String getRandomKey() {
        SecureRandom random = new SecureRandom();
        long randomKey = random.nextLong();
        return String.valueOf(randomKey);
    }
    
}