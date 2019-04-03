package com.yitong.util.cert;

import org.apache.commons.codec.binary.Base64;

import com.alibaba.fastjson.JSONObject;

/**
 * @author chengqg
 * 
 */
public class SecureUtil {
	public static String encrypt(String msg) {
		JSONObject json = JSONObject.parseObject(msg);
		//加签
		SDKUtil.sign(json, "utf-8");
		//加密
		String aesRandomKey = AlgorithmUtil.getAESRandomKey();
		
		String serverData = "";
		String randomKeyEncrypted = "";
		try {
			serverData = AlgorithmUtil.encryptWithAES(json.toJSONString(), aesRandomKey);
			String publicKey = new String(Base64.encodeBase64(CertUtil.getPublicKey().getEncoded()));
			randomKeyEncrypted = AlgorithmUtil.encryptWithRSA(aesRandomKey, publicKey);
		} catch (Exception e) {
			System.out.println("加密失败");
		}
		
		JSONObject req = new JSONObject();
		req.put("bizData", serverData);
		req.put("randomKeyEncrypted", randomKeyEncrypted);
		return req.toJSONString();
	}

	public static String decrypt(String msg)  {
		JSONObject rsp = JSONObject.parseObject(msg);
		//解密
		String randomKeyEncrypted = rsp.getString("randomKeyEncrypted");
        String randomKey = "";
        String decrptStr = "";
        String privateKey = new String(Base64.encodeBase64(CertUtil.getPrivateKey().getEncoded()));
		try {
			randomKey = AlgorithmUtil.decryptWithRSA(randomKeyEncrypted, privateKey);
			decrptStr = AlgorithmUtil.decryptWithAES(rsp.getString("bizData"), randomKey);
			System.out.println(decrptStr);
		} catch (Exception e) {
			System.out.println("解密失败");
		}
		
		//验签
		JSONObject bizData = JSONObject.parseObject(decrptStr);
		boolean result = SDKUtil.validate(bizData, "utf-8");
		if (!result) {
			System.out.println("验签失败");
		}
		
		return bizData.toJSONString();
	}
	
	public static void main(String[] args) {
		String s = "{\"head\":{\"appid\":\"22003\",\"elcplatid\":\"22003\",\"reqtm\":\"20190103164938\",\"reqdt\":\"2019-01-03\",\"reqsn\":\"LU201901030001022245\"},\"body\":{\"OldTrnDt\":\"2018-12-21\",\"OldTrnSeqNo\":\"LU201812210000886401\",\"OperFlg\":\"4\"}}";
		String l = encrypt(s);
		System.out.println(l);
		System.out.println(decrypt(l));
	}
}
