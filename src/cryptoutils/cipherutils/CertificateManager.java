
package cryptoutils.cipherutils;

import java.io.*;
import java.security.PublicKey;
import java.security.cert.*;

public class CertificateManager {
    /**
     * Returns a Certificate object read from a X.509 formatted certificate file.
     * @param filename  a path to the certificate file
     * @return the certificate read from file
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws IOException 
     */
    public static Certificate readCertFromFile(String filename) throws CertificateException, FileNotFoundException, IOException  {
        try(FileInputStream fis = new FileInputStream(filename);
        BufferedInputStream bis = new BufferedInputStream(fis)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            java.security.cert.Certificate cert = null;
            while (bis.available() > 0) cert = cf.generateCertificate(bis);
            return cert;
        } catch(Exception e) {
            return null;
        }
    }
    /**
     * Verifies integrity of Certificate toVerify with a trusted Certificate trustedAuthority
     * @param toVerify          certificate to be validated
     * @param trustedAuthority  trusted authority certificate
     * @return boolean indicating whether the Certificate toVerify is valid or not
     */
    public static boolean verifyCertificate(Certificate toVerify,Certificate trustedAuthority) {
        try {
            PublicKey authPublicKey = trustedAuthority.getPublicKey();
            toVerify.verify(authPublicKey);
            return true;
        } catch(Exception e) {
            return false;
        }
    }
    /**
     * Verifies integrity and date-validity of a X509Certificate object with a trusted Certificate trustedAuthority
     * @param toVerify          certificate to be validated
     * @param trustedAuthority  trusted authority certificate
     * @return boolean indicating whether the Certificate toVerify is valid or not
     */
    public static boolean verifyCertificate(X509Certificate toVerify,Certificate trustedAuthority) {
        try {
            boolean validity = verifyCertificate((Certificate)toVerify, trustedAuthority);
            toVerify.checkValidity();
            return validity;
        } catch(Exception e) {
            return false;
        }
    }
            
}
