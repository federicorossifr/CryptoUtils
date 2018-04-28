package cryptoutils.cipherutils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;

public class SignatureManager {
    /**
     * Signs byte[] object representing data by means of a PrivateKey
     * @param data  the data to be signed
     * @param alg   the algorithm to be used to sign
     * @param key   the PrivateKey object to be used to sign
     * @return  byte[] object representing the signature
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException 
     */
    public static byte[] sign(byte[] data,String alg,PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(alg);
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }
    
    /**
     * Verify a sigature using a PublicKey
     * @param data
     * @param sign
     * @param alg the algorithm to be used
     * @param key the PublicKey object to be used
     * @return  boolean object stating whether the message is correctly signed or not
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException 
     */
    public static boolean verify(byte[] data,byte[] sign,String alg,PublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        try {
            Signature sig = Signature.getInstance(alg);
            sig.initVerify(key);
            sig.update(data);
            boolean res = sig.verify(sign);
            return res;
        } catch(Exception e) {
            return false;
        }
    }
    /**
     * Verify a signature using a Certificate object
     * @param data
     * @param sign
     * @param alg
     * @param cert  The certificate used to verify the signature
     * @return
     * @throws SignatureException
     * @throws NoSuchAlgorithmException 
     */
    public static boolean verify(byte[] data,byte[] sign,String alg,Certificate cert) throws SignatureException, NoSuchAlgorithmException {
        try {
            Signature sig = Signature.getInstance(alg);
            sig.initVerify(cert);
            sig.update(data);
            boolean res = sig.verify(sign);
            return res;
        } catch(Exception e) {
            return false;
        }
    }
}
