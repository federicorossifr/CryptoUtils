
package cryptoutils.communication;

import cryptoutils.cipherutils.CryptoManager;
import cryptoutils.cipherutils.SignatureManager;
import cryptoutils.messagebuilder.MessageBuilder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.util.*;
import java.security.PrivateKey;

public class TrustedPartyRMIServer implements TrustedPartyInterface{
    private ArrayList<Certificate> certStore;
    private final String authorityCertificateFile;
    private final String authorityKeyFile;
    private PrivateKey authKey = null;
    private String crlName = null;
    
    /**
     * p
     * @param authorityCertificateFile the filename of the authority certificate 
     * @param authorityKeyFile the filename of the authority private key
     */
    public TrustedPartyRMIServer(String authorityCertificateFile,String authorityKeyFile,String crlName) {
        this.authorityCertificateFile= authorityCertificateFile;
        this.authorityKeyFile = authorityKeyFile;
        this.crlName = crlName;
        try{
            this.authKey = CryptoManager.readRSAPrivateKeyFromPEMFile(authorityKeyFile);
        }catch(Exception ex){
            ex.printStackTrace();
            System.exit(-1);
        }
    }
    /**
     * 
     * @param nonce
     * @return byte[] representing the CRL list
     * @throws RemoteException 
     */
    @Override
    public byte[] getCRL(byte[] nonce) throws RemoteException {try {
        byte[] crlBytes = Files.readAllBytes(Paths.get(crlName));
        System.out.println(new String(crlBytes));
        byte[] noncedCrlBytes = MessageBuilder.concatBytes(crlBytes,nonce);
        byte[] signatureBytes = SignatureManager.sign(noncedCrlBytes,"SHA256withRSA", authKey);
        byte[] signatureLength = MessageBuilder.toByteArray(signatureBytes.length);
        byte[] returnMessage = MessageBuilder.concatBytes(signatureLength,signatureBytes,noncedCrlBytes);
        return returnMessage;
        } catch (Exception ex) {ex.printStackTrace(); return null;}
    }
    
}
