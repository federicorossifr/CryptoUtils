package cryptoutils.hashutils;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HashManager {
    /**
     * Returns a String object composed by the hexadecimal representation of each byte[] array element
     * @param bytes the byte[] array to be converted
     * @return the hexadecimal String object
     */
    public static String toHexString(byte[] bytes) {
            Formatter formatter = new Formatter();
            for (byte b : bytes) {
                    formatter.format("%02x:", b);
            }
            String tmp = formatter.toString();
            return tmp.substring(0, tmp.length() - 1);
    }
    
    /**
     * Compute the hash of the byte[] object using the algorithm specified by String object alg
     * @param bytes the bytes to be hashed
     * @param alg   the algorithm to be used
     * @return  the byte[] object representing the hash
     * @throws NoSuchAlgorithmException 
     */
    public static byte[] doHash(byte[] bytes,String alg) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(alg);
        return md.digest(bytes);
    }
    
    /**
     * Compute a Message authentication code over the byte[] object, using the algorithm in String object alg and String object key as secret key
     * @param bytes 
     * @param key the secret key
     * @param alg
     * @return  the byte[] object representing the MAC
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException 
     */
    public static byte[] doMAC(byte[] bytes,String key,String alg) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec signKey = new SecretKeySpec(key.getBytes(),alg);
        Mac m = Mac.getInstance(alg);
        m.init(signKey);
        return m.doFinal(bytes);
    }
    
    /**
     * Compare the mac provided with the mac computed over data using key as secret key and alg as algorithm
     * It uses two-pass hash algorithm to avoid timing attacks.
     * @param data
     * @param mac
     * @param key
     * @param alg
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException 
     */
    public static boolean compareMAC(byte[] data,byte[] mac,String key,String alg) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] computedMac = doMAC(data,key,alg);
        byte[] computedMacMAC = doMAC(computedMac,key,alg);
        byte[] macMAC = doMAC(mac,key,alg);
        return MessageDigest.isEqual(computedMacMAC, macMAC);
    }
}
