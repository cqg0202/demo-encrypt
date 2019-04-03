package com.yitong.util.cert;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * 证书工具类
 * @author chengqg
 * 
 */
public class CertUtil {
	/** 证书容器. */
	private  static KeyStore keyStore = null;
	
	private  static X509Certificate validateCert = null;
	
	/**
	 * 初始化证书容器的方法
	 */
	static SDKConfig config = new SDKConfig();

	/**
	 * 加载证书仓库
	 */
	public  static void initSignCert(SDKConfig config) {
		if (null != keyStore) {
			keyStore = null;
		}
		keyStore = getKeyInfo(config.getKeyStorePath(), config.getKeyStorePwd(), config.getKeyStoreType());
	}

	

	

	/**
	 * 获取私钥
	 * 
	 * @return
	 */
	public static PrivateKey getPrivateKey() {
		try {
			initSignCert(config);
			Enumeration<String> aliasenum = keyStore.aliases();
			String keyAlias = null;
			if (aliasenum.hasMoreElements()) {
				keyAlias = aliasenum.nextElement();
			}
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias,
					config.getKeyStorePwd().toCharArray());
			return privateKey;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 获取公钥
	 * @return
	 */
	public static  PublicKey getPublicKey() {
		CertificateFactory cf = null;
		FileInputStream in = null;
		try {
			cf = CertificateFactory.getInstance("X.509");
			File file = new File(config.getPubKeyPath());
				in = new FileInputStream(file.getAbsolutePath());
				validateCert = (X509Certificate) cf.generateCertificate(in);
				return validateCert.getPublicKey();
		} catch (CertificateException e) {
			e.printStackTrace();
			return null;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} finally {
			if (null != in) {
				try {
					in.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
	

	/**
	 * 将证书文件读取为证书存储对象
	 * 
	 * @param pfxkeyfile
	 *            证书文件名
	 * @param keypwd
	 *            证书密码
	 * @param type
	 *            证书类型
	 * @return 证书对象
	 */
	public  static KeyStore getKeyInfo(String pfxkeyfile, String keypwd,
			String type) {
		try {
			KeyStore ks = null;
			if ("JKS".equals(type)) {
				ks = KeyStore.getInstance(type);
			} else if ("PKCS12".equals(type)) {
				Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
				ks = KeyStore.getInstance(type);
			}
			FileInputStream fis = new FileInputStream(pfxkeyfile);
			char[] nPassword = null;
			nPassword = null == keypwd || "".equals(keypwd.trim()) ? null
					: keypwd.toCharArray();
			if (null != ks){
				ks.load(fis, nPassword);
			}
			fis.close();
			return ks;
		} catch (Exception e) {
			if (Security.getProvider("BC") == null) {
//				System.out.println("BC Provider not installed.");
			}
			e.printStackTrace();
			if ((e instanceof KeyStoreException) && "PKCS12".equals(type)) {
				Security.removeProvider("BC");
			}
			return null;
		}
	}
}
