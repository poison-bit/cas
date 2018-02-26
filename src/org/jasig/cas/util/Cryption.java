package org.jasig.cas.util;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

/**
 * 通用加密解密工具
 *
 * @author PengLian
 */
public class Cryption {

    private final static String sKey  = "cqt_Tg8wqx";
    private static Logger logger = Logger.getLogger(Cryption.class);

    /**
     * 初始化加密Cipher
     * @return
     * @throws Exception
     */
    public static Cipher initEnCipher() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed(sKey.getBytes());
        keyGenerator.init(128, secureRandom);
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] codeFormat = secretKey.getEncoded();
        SecretKeySpec key = new SecretKeySpec(codeFormat, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher;
    }

    /**
     * 初始化加密Cipher
     * @return
     * @throws Exception
     */
    public static Cipher initDeCipher() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed(sKey.getBytes());
        keyGenerator.init(128, secureRandom);
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] codeFormat = secretKey.getEncoded();
        SecretKeySpec key = new SecretKeySpec(codeFormat, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher;
    }

    /**
     * 加密输入�?
     * @param iStream
     * @return
     */
    public static InputStream encryptStream(InputStream iStream) throws Exception {
        return new CipherInputStream(iStream, initEnCipher());
    }

    /**
     * 加密输出�?
     * @param oStream
     * @return
     */
    public static OutputStream decryptStream(OutputStream oStream) throws Exception {
        return new CipherOutputStream(oStream, initDeCipher());
    }

    /**
     * 对字符串加密
     *
     * @param str
     * @return
     * @throws Exception
     */

    public static String enCrytor(String str) throws Exception {
        byte[] src =  str.getBytes();
        byte[] cipherByte = initEnCipher().doFinal(src);
        return parseByte2HexStr(cipherByte);
    }

    /**
     * 对字符串解密
     *
     * @param str
     * @return
     * @throws Exception
     */

    public static String deCrytor(String str) throws Exception {
        byte[] src = parseHexStr2Byte(str);
        byte[] cipherByte = initDeCipher().doFinal(src);
        return new String(cipherByte);
    }

    /**
     * 将二进制转换�?16进制
     * @param buf
     * @return
     */
    public static String parseByte2HexStr(byte buf[]) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }

    /**
     * �?16进制转换为二进制
     * @param hexStr
     * @return
     */
    public static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1)
            return null;
        byte[] result = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2),
                    16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }

    /**
     * 生成传入字符串的MD5�?
     * @param source
     * @return
     */
    public static String string2MD5(String source){
        MessageDigest md5 = null;
        StringBuilder sb = new StringBuilder("");
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (Exception e) {
            logger.error("获取MD5加密器失�?", e);
            e.printStackTrace();
        }
        md5.update(source.getBytes());
        byte b[] = md5.digest();

        int i;
        for (int offset = 0; offset < b.length; offset++) {
            i = b[offset];
            if (i < 0){
                i += 256;
            }
            if (i < 16) {
                sb.append("0");
            }
            sb.append(Integer.toHexString(i));
        }
        return sb.toString();
    }
    
    /**
     * AppData加密
     * @param data
     * @return
     * @throws Exception
     */
    public static String enCrytorAppData(String data) throws Exception {
    	byte[] salt = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF };
    	PBEKeySpec myKeyspec = new PBEKeySpec(sKey.toCharArray(), salt, 10000, 128);
    	byte[] iv = { 0xA, 1, 0xB, 5, 4, 0xF, 7, 9, 0x17, 3, 1, 6, 8, 0xC, 0xD, 91 };
    	IvParameterSpec IV;
    	SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    	SecretKey sk = keyfactory.generateSecret(myKeyspec);
    	byte[] skAsByteArray = sk.getEncoded();
    	SecretKeySpec skforAES = new SecretKeySpec(skAsByteArray, "AES");
    	IV = new IvParameterSpec(iv);
    	Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    	c.init(Cipher.ENCRYPT_MODE, skforAES, IV);
    	byte[] re = c.doFinal(data.getBytes());
    	return Base64.getEncoder().encodeToString(re);
    }
    
    /**
     * AppData解密
     * @param data
     * @return
     * @throws Exception
     */
    public static String deCrytorAppData(String data) throws Exception {
    	byte[] salt = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF };
    	PBEKeySpec myKeyspec = new PBEKeySpec(sKey.toCharArray(), salt, 10000, 128);
    	byte[] iv = { 0xA, 1, 0xB, 5, 4, 0xF, 7, 9, 0x17, 3, 1, 6, 8, 0xC, 0xD, 91 };
    	IvParameterSpec IV;
    	SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    	SecretKey sk = keyfactory.generateSecret(myKeyspec);
    	byte[] skAsByteArray = sk.getEncoded();
    	SecretKeySpec skforAES = new SecretKeySpec(skAsByteArray, "AES");
    	IV = new IvParameterSpec(iv);
    	Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    	c.init(Cipher.DECRYPT_MODE, skforAES, IV);
    	byte[] re = c.doFinal(Base64.getDecoder().decode(data));
    	return new String(re);
    }
    
    public static void main(String[] args) throws Exception {
		System.out.println(deCrytorAppData("ApVs/WbR/4/iLlmF6GfRXZUKqFy34UkDhl8Zob7Gh7Y1JJsAUcjy2fTz09Z4SYqNZLrPOR4T9HBi7K8bvrnkkEBRIWvJv6lSvtCKCA9pAUT7QeJJTpShE3msG+xMU7w1"));
	}

}
