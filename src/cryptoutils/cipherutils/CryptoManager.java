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
    
    /**
     * Computes the initialization vector for CBC encryption mode computing the SHA-256 hash
     * of the Integer object iv
     * @param iv    the integer to use as IV
     * @return      the IVParameterSpec object that represents the 16 bytes IV
     * @throws NoSuchAlgorithmException 
     */
    private static IvParameterSpec computeIV(int iv) throws NoSuchAlgorithmException { 
        byte[] ivBytes = ByteBuffer.allocate(4).putInt(iv).array();    
        byte[] ivDigest = MessageDigest.getInstance("SHA-256").digest(ivBytes);
        return new IvParameterSpec(MessageBuilder.extractFirstBytes(ivDigest, 16));
    }
    
    /**
     * Transforms a String object representing a secret key in the correspondent
     * SecretKeySpec object
     * @param s     the secret key
     * @param alg   the encryption algorithm used
     * @return      the SecretKeySpec object representing the key
     * @throws UnsupportedEncodingException 
     */
    private static SecretKeySpec computeKey(String s,String alg) throws UnsupportedEncodingException {        
        return new SecretKeySpec(s.getBytes("UTF-8"),alg);       
    }
    
    /**
     * Encrypts an byte[] object representing the plainText using the String object key
     * as key and Integer object iv as initialization vector
     * @param plainText the plaintext bytes
     * @param key       the secret key
     * @param iv        the initialization vector
     * @return          byte[] object containing both ciphertext and iv bytes
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException 
     */
    public static byte[] encryptCBC(byte[] plainText,String key,int iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = computeIV(iv);
        byte[] ivBytes = ivSpec.getIV();
        cipher.init(Cipher.ENCRYPT_MODE,computeKey(key,"AES"),ivSpec);
        byte[] encrypted = cipher.doFinal(plainText);
        byte[] encryptedIV = MessageBuilder.concatBytes(encrypted, ivBytes);
        return encryptedIV;
    }
    
    /**
     * Decrypts the byte[] object representing the cipherText with the Strign object representing the key
     * @param cipherText    the ciphertext bytes
     * @param key           the string
     * @return              byte[] object representing the plaintext
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException 
     */
    public static byte[] decryptCBC(byte[] cipherText,String key) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException { 
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");      
        byte[] ivBytes = MessageBuilder.extractLastBytes(cipherText, 16);
        byte[] cipherTextNoIV = MessageBuilder.extractFirstBytes(cipherText, cipherText.length-16);
        cipher.init(Cipher.DECRYPT_MODE,computeKey(key,"AES"),new IvParameterSpec(ivBytes));
        return cipher.doFinal(cipherTextNoIV);
    } 
    
    
    /**
     * Encrypts the byte[] object representing the plaintext using the PublicKey object key by means
     * of RSA 
     * @param data the plaintext
     * @param key  the PublicKey
     * @return  byte[] object representing the ciphertext
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public static byte[] encryptRSA(byte[] data,PublicKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchPaddingException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
    
    /**
     * Decrypts the byte[] object representing a cipherText using the PrivateKey object key
     * @param cipherText the cipherText bytes
     * @param key   the PrivateKey
     * @return  byte[] array representing the plainText
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public static byte[] decryptRSA(byte[] cipherText,PrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchPaddingException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }    
    
    
    /**
     * Reads a PrivateKey from a formatted PKCS8 PEM file
     * @param filename  the key file path
     * @return  the PrivateKey object read
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IOException 
     */
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
