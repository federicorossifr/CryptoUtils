
package cryptoutils.cipherutils;

import java.io.*;
import java.security.PublicKey;
import java.security.cert.*;

public class CertificateManager {
    public static Certificate readCertFromFile(String filename) throws CertificateException, FileNotFoundException, IOException  {
        FileInputStream fis = new FileInputStream(filename);
        BufferedInputStream bis = new BufferedInputStream(fis);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        java.security.cert.Certificate cert = null;
        while (bis.available() > 0) cert = cf.generateCertificate(bis);
        return cert;
    }
    
    public static boolean verifyCertificate(Certificate toVerify,Certificate trustedAuthority) {
        try {
            PublicKey authPublicKey = trustedAuthority.getPublicKey();
            toVerify.verify(authPublicKey);
            return true;
        } catch(Exception e) {
            return false;
        }
    }
            
}
