package cryptoutils.cipherutils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class SignatureManager {
    public static byte[] sign(byte[] data,String alg,PrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(alg);
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }
    
    public static boolean verify(byte[] data,byte[] sign,String alg,PublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance(alg);
        sig.initVerify(key);
        sig.update(data);
        return sig.verify(sign);
    }
}
