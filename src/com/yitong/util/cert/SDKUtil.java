package com.yitong.util.cert;

import java.io.UnsupportedEncodingException;
import java.security.PublicKey;

import org.apache.commons.codec.binary.Base64;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.serializer.SerializerFeature;

/**
 * @author chengqg
 * 
 */
public class SDKUtil {

	/**
	 * 生成签名值(SHA1摘要算法),供商户调用
	 * 
	 * @param data
	 *            待签名数据Map键值对形式
	 * @param encoding
	 *            编码
	 * @return 签名是否成功
	 */
	public static boolean sign(JSONObject req, String encoding) {
//		System.out.println("--------------签名开始--------------");
		if (isEmpty(encoding)) {
			encoding = "UTF-8";
		}
		
		//按字母顺序对字段排序
		String reqStr = JSONObject.toJSONString(req, SerializerFeature.MapSortField);
//		System.out.println("签名前字符串=[" + reqStr + "]");
		/**
		 * 签名\base64编码
		 */
		byte[] byteSign = null;
		String stringSign = null;
		try {
			// 通过SHA1进行摘要并转16进制
			byte[] signDigest = RSAUtil.sha1X16(reqStr, encoding);
//			System.out.println("SHA1->16进制转换后的摘要=[" + new String(signDigest) + "]");
			
			//计算签名
			byteSign = Base64.encodeBase64(RSAUtil.signBySoft(
					CertUtil.getPrivateKey(), signDigest));
			stringSign = new String(byteSign);
//			System.out.println("签名值=[" + stringSign + "]");
			// 设置签名域值
			req.put("signature", stringSign);
//			System.out.println("签名后字符串=[" + JSONObject.toJSONString(req, SerializerFeature.MapSortField) + "]");
//			System.out.println("--------------签名结束--------------");
			return true;
		} catch (Exception e) {
//			System.out.println(e);
			return false;
		}
	}

	

	/**
	 * 验证签名(SHA-1摘要算法)
	 * 
	 * @param resData
	 *            返回报文数据
	 * @param encoding
	 *            编码格式
	 * @return
	 */
	public static boolean validate(JSONObject rsp, String encoding) {
//		System.out.println("--------------验签开始--------------");
		if (isEmpty(encoding)) {
			encoding = "UTF-8";
		}
		try {
			//获取并移除签名值
			String signature = (String) rsp.remove("signature");
//			System.out.println("返回报文中signature=[" + signature + "]");
			PublicKey pkey = CertUtil.getPublicKey();
			//按字母顺序排序
			String rspStr = JSONObject.toJSONString(rsp, SerializerFeature.MapSortField);
//			System.out.println("返回报文中(不含signature域)的域=[" + rspStr + "]");
			
			boolean result = RSAUtil.validateSignBySoft(pkey, Base64.decodeBase64(signature.getBytes(encoding)), RSAUtil.sha1X16(rspStr, encoding));
//			System.out.println("--------------验签结束--------------");
			return result;
		} catch (UnsupportedEncodingException e) {
//			System.out.println(e);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	/**
	 * 判断字符串是否为NULL或空
	 * 
	 * @param s
	 *            待判断的字符串数据
	 * @return 判断结果 true-是 false-否
	 */
	public static boolean isEmpty(String s) {
		return null == s || "".equals(s.trim());
	}
}
