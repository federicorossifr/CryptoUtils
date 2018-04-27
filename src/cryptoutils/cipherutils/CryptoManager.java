package cryptoutils.cipherutils;

import java.io.*;
import java.nio.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import cryptoutils.messagebuilder.MessageBuilder;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.Paths;
import java.security.spec.*;
import java.util.Base64;

public class CryptoManager {
    private static final String PKCS8_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PKCS8_TRAILER= "-----END PRIVATE KEY-----";
    private static final String NEW_LINE = System.getProperty("line.separator");
    private static IvParameterSpec computeIV(int iv) throws NoSuchAlgorithmException { 
        byte[] ivBytes = ByteBuffer.allocate(4).putInt(iv).array();    
        byte[] ivDigest = MessageDigest.getInstance("SHA-256").digest(ivBytes);
        return new IvParameterSpec(MessageBuilder.extractFirstBytes(ivDigest, 16));
    }
    
    private static SecretKeySpec computeKey(String s,String alg) throws UnsupportedEncodingException {        
        return new SecretKeySpec(s.getBytes("UTF-8"),alg);       
    }
    
    public static byte[] encryptCBC(byte[] plainText,String key,int iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = computeIV(iv);
        byte[] ivBytes = ivSpec.getIV();
        cipher.init(Cipher.ENCRYPT_MODE,computeKey(key,"AES"),ivSpec);
        byte[] encrypted = cipher.doFinal(plainText);
        byte[] encryptedIV = MessageBuilder.concatBytes(encrypted, ivBytes);
        return encryptedIV;
    }
    
    public static byte[] decryptCBC(byte[] cipherText,String key) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException { 
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");      
        byte[] ivBytes = MessageBuilder.extractLastBytes(cipherText, 16);
        byte[] cipherTextNoIV = MessageBuilder.extractFirstBytes(cipherText, cipherText.length-16);
        cipher.init(Cipher.DECRYPT_MODE,computeKey(key,"AES"),new IvParameterSpec(ivBytes));
        return cipher.doFinal(cipherTextNoIV);
    } 
    
    public static byte[] encryptRSA(byte[] data,PublicKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchPaddingException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
    
    public static byte[] decryptRSA(byte[] cipherText,PrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchPaddingException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }    
    
    public static PrivateKey readRSAPrivateKeyFromPEMFile(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] privateKey = Files.readAllBytes(Paths.get(filename));
        String privateKeyString = new String(privateKey);
        String privPEM=privateKeyString.replace(PKCS8_HEADER, "");
        privPEM=privPEM.replace(PKCS8_TRAILER,"");
        privPEM=privPEM.replaceAll(NEW_LINE, "");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privPEM));
        PrivateKey pk = kf.generatePrivate(keySpec);
        return pk;
    }
}
