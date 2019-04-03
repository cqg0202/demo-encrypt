package com.yitong.util.cert;

import java.util.ResourceBundle;
/**
 * 读取配置文件，获取证书相关路径
 * @author chengqg
 *
 */

public class SDKConfig {

	/** 签名证书路径. */
	private String keyStorePath;
	
	private String pubKeyPath;
	/** 签名证书密码. */
	private String keyStorePwd;
	/** 签名证书类型. */
	private String keyStoreType;
	/** 加密公钥证书路径. */

	/** 配置文件中签名证书路径常量. */
	public static final String SDK_KEYSTORE_PATH = "keyStore.path";
	public static final String SDK_PUBKEY_PATH = "pubKey.path";
	


	/** 配置文件中签名证书密码常量. */
	public static final String SDK_KEYSTORE_PWD = "keyStore.pwd";
	/** 配置文件中签名证书类型常量. */
	public static final String SDK_KEYSTORE_TYPE = "keyStore.type";
	
	SDKConfig() {
		loadProperties();
	}
	

	/**
	 * 根据传入的 {@link #load(java.util.Properties)}对象设置配置参数
	 * 
	 * @param pro
	 */
	public void loadProperties() {
		String value = "";
		try {
			value =  ResourceBundle.getBundle("AUTH_CERT").getString(SDK_KEYSTORE_PATH);
			if (!SDKUtil.isEmpty(value)) {
				setKeyStorePath(value.trim());
			}
			
			value =  ResourceBundle.getBundle("AUTH_CERT").getString(SDK_PUBKEY_PATH);
			if (!SDKUtil.isEmpty(value)) {
				setPubKeyPath(value.trim());
			}
			
			value =  ResourceBundle.getBundle("AUTH_CERT").getString(SDK_KEYSTORE_PWD);
			if (!SDKUtil.isEmpty(value)) {
				setKeyStorePwd(value.trim());
			}
			
			value =  ResourceBundle.getBundle("AUTH_CERT").getString(SDK_KEYSTORE_TYPE);
			if (!SDKUtil.isEmpty(value)) {
				setKeyStoreType(value.trim());
			}
			
		} catch (Exception e) {
			System.out.println(e);
			// TODO: handle exception
		}

	}
	
	public String getKeyStorePath() {
		return keyStorePath;
	}


	public void setKeyStorePath(String keyStorePath) {
		this.keyStorePath = keyStorePath;
	}

	public String getPubKeyPath() {
		return pubKeyPath;
	}


	public void setPubKeyPath(String pubKeyPath) {
		this.pubKeyPath = pubKeyPath;
	}
	public String getKeyStorePwd() {
		return keyStorePwd;
	}


	public void setKeyStorePwd(String keyStorePwd) {
		this.keyStorePwd = keyStorePwd;
	}


	public String getKeyStoreType() {
		return keyStoreType;
	}


	public void setKeyStoreType(String keyStoreType) {
		this.keyStoreType = keyStoreType;
	}


}
