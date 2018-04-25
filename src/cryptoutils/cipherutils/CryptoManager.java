package cryptoutils.cipherutils;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import cryptoutils.messagebuilder.MessageBuilder;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class CryptoManager {
    
    private static IvParameterSpec computeIV(int iv) throws NoSuchAlgorithmException { //HERE WE SHOULD NEED MORE BYTES
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
        String privPEM=privateKeyString.replace("-----BEGIN PRIVATE KEY-----", "");
        privPEM=privPEM.replace("-----END PRIVATE KEY-----","");
        privPEM=privPEM.replaceAll(System.getProperty("line.separator"), "");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privPEM));
        PrivateKey pk = kf.generatePrivate(keySpec);
        return pk;
    }
}
