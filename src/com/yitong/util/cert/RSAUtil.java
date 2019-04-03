package com.yitong.util.cert;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA相关工具
 * @author chengqg
 * 
 */
public class RSAUtil {

    /**
     * 加密方式
     */
    public static final String KEY_ALGORITHM = "RSA";
    /**
     * 签名算法
     */
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    /**
     * 公钥算法
     */
    public static final String PUBLIC_KEY = "RSAPublicKey";
    /**
     * 私钥算法
     */
    public static final String PRIVATE_KEY = "RSAPrivateKey";
    
	/**
	 * 算法常量： SHA1
	 */
	private static final String ALGORITHM_SHA1 = "SHA-1";

	/**
	 * 算法常量：SHA1withRSA
	 */
	private static final String BC_PROV_ALGORITHM_SHA1RSA = "SHA1withRSA";

    public static byte[] decryptBASE64(String key){
        return Base64.decodeBase64(key);
    }

    public static String encryptBASE64(byte[] bytes){
        return Base64.encodeBase64String(bytes);
    }


    /**
     * 解密<br>
     * 私钥解密
     * @param data 加密数据
     * @param key 私钥
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {
        // 对密钥解密
        byte[] keyBytes = decryptBASE64(key);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * 解密 <br>
     * 用私钥解密
     * @param data 加密数据
     * @param key 私钥
     * @return 消息
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(String data, String key) throws Exception {
        return decryptByPrivateKey(decryptBASE64(data), key);
    }

    /**
     * 加密<br>
     * 用公钥加密
     * @param data 待加密消息
     * @param key 公钥
     * @return 密文
     * @throws Exception
     */
    public static String encryptByPublicKey(String data, String key) throws Exception {
        // 对公钥解密
        byte[] keyBytes = decryptBASE64(key);
        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptBASE64(cipher.doFinal(data.getBytes()));
    }
    
    /**
   	 * sha1计算.
   	 * 
   	 * @param datas
   	 *            待计算的数据
   	 * @return 计算结果
   	 */
   	public static byte[] sha1(byte[] data) {
   		MessageDigest md = null;
   		try {
   			md = MessageDigest.getInstance(ALGORITHM_SHA1);
   			md.reset();
   			md.update(data);
   			return md.digest();
   		} catch (Exception e) {
   			e.printStackTrace();
   			return null;
   		}
   	}
   	
   	/**
   	 * sha1计算
   	 * 
   	 * @param datas
   	 *            待计算的数据
   	 * @param encoding
   	 *            字符集编码
   	 * @return
   	 */
   	public static byte[] sha1(String datas, String encoding) {
   		try {
   			return sha1(datas.getBytes(encoding));
   		} catch (UnsupportedEncodingException e) {
   			return null;
   		}
   	}
   	/**
   	 * sha1计算后进行16进制转换
   	 * 
   	 * @param data
   	 *            待计算的数据
   	 * @param encoding
   	 *            编码
   	 * @return 计算结果
   	 */
   	public static byte[] sha1X16(String data, String encoding) {
   		byte[] bytes = sha1(data, encoding);
   		StringBuilder sha1StrBuff = new StringBuilder();
   		for (int i = 0; i < bytes.length; i++) {
   			if (Integer.toHexString(0xFF & bytes[i]).length() == 1) {
   				sha1StrBuff.append("0").append(
   						Integer.toHexString(0xFF & bytes[i]));
   			} else {
   				sha1StrBuff.append(Integer.toHexString(0xFF & bytes[i]));
   			}
   		}
   		try {
   			return sha1StrBuff.toString().getBytes(encoding);
   		} catch (UnsupportedEncodingException e) {
   			e.printStackTrace();
   			return null;
   		}
   	}
   	
   	/**
   	 * 软签名
   	 * 
   	 * @param privateKey
   	 *            私钥
   	 * @param data
   	 *            待签名数据
   	 * @param signMethod
   	 *            签名方法
   	 * @return 结果
   	 * @throws Exception
   	 */
   	public static byte[] signBySoft(PrivateKey privateKey, byte[] data)
   			throws Exception {
   		byte[] result = null;
   		Signature st = Signature.getInstance(BC_PROV_ALGORITHM_SHA1RSA);
   		st.initSign(privateKey);
   		st.update(data);
   		result = st.sign();
   		return result;
   	}

   	/**
   	 * 软验证签名
   	 * 
   	 * @param publicKey
   	 *            公钥
   	 * @param signData
   	 *            签名数据
   	 * @param srcData
   	 *            摘要
   	 * @param validateMethod
   	 *            签名方法.
   	 * @return
   	 * @throws Exception
   	 */
   	public static boolean validateSignBySoft(PublicKey publicKey,
   			byte[] signData, byte[] srcData) throws Exception {
   		Signature st = Signature.getInstance(BC_PROV_ALGORITHM_SHA1RSA);
   		st.initVerify(publicKey);
   		st.update(srcData);
   		return st.verify(signData);
   	}
}
