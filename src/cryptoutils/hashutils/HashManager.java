package cryptoutils.hashutils;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HashManager {
    public static String toHexString(byte[] bytes) {
            Formatter formatter = new Formatter();
            for (byte b : bytes) {
                    formatter.format("%02x", b);
            }
            return formatter.toString();
    }
    
    
    public static byte[] doHash(byte[] bytes,String alg) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(alg);
        return md.digest(bytes);
    }
    
    public static byte[] doMAC(byte[] bytes,String key,String alg) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec signKey = new SecretKeySpec(key.getBytes(),alg);
        Mac m = Mac.getInstance(alg);
        m.init(signKey);
        return m.doFinal(bytes);
    }
    
    public static boolean compareMAC(byte[] data,byte[] mac,String key,String alg) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] computedMac = doMAC(data,key,alg);
        byte[] computedMacMAC = doMAC(computedMac,key,alg);
        byte[] macMAC = doMAC(mac,key,alg);
        return MessageDigest.isEqual(computedMacMAC, macMAC);
    }
}
