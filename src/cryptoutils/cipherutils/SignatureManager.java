package cryptoutils.cipherutils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;

public class SignatureManager {
    public static byte[] sign(byte[] data,String alg,PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(alg);
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }
    
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
