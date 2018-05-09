
package cryptoutils.communication;

import cryptoutils.cipherutils.CertificateManager;
import cryptoutils.cipherutils.CryptoManager;
import cryptoutils.cipherutils.SignatureManager;
import cryptoutils.messagebuilder.MessageBuilder;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import cryptoutils.openssl.OpenSSLCliBindings;
import java.rmi.server.RemoteServer;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;

public class TrustedPartyRMIServer implements TrustedPartyInterface{
    private ArrayList<Certificate> certStore;
    private final String authorityCertificateFile;
    private final String authorityKeyFile;
    private PrivateKey authKey = null;
    
    /**
     * p
     * @param authorityCertificateFile the filename of the authority certificate 
     * @param authorityKeyFile the filename of the authority private key
     */
    public TrustedPartyRMIServer(String authorityCertificateFile,String authorityKeyFile) {
        certStore = loadArray();
        this.authorityCertificateFile= authorityCertificateFile;
        this.authorityKeyFile = authorityKeyFile;
        try{
            this.authKey = CryptoManager.readRSAPrivateKeyFromPEMFile(authorityKeyFile);
        }catch(Exception ex){
            ex.printStackTrace();
            System.exit(-1);
        }
    }
    
    /**
     * Load the certificate store from file. If file is not found, a new store is created
     * @return the TreeMap representing the certificate store
     */
    private ArrayList<Certificate> loadArray()  {
        try(FileInputStream fis = new FileInputStream("cstore.bin");
            ObjectInputStream bis = new ObjectInputStream(fis);) {
            ArrayList<Certificate> array = (ArrayList<Certificate>) bis.readObject();
            return array;
        } catch(Exception e) {
            e.printStackTrace();
            return new ArrayList<>();
        }
    }
    
    /**
     * Save the current certificate store into a binary file.
     */
    private void backupArray() {
        try(FileOutputStream fos = new FileOutputStream("cstore.bin");
            ObjectOutputStream bos = new ObjectOutputStream(fos);)
        {
            bos.writeObject(certStore);
        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Register an user into the certificate store by signing its certificate signing request represented
     * by byte[] object
     * @param csrContent the byte[] array containing the csr request
     * @return  the signed Certificate object
     * @throws RemoteException 
     */
    @Override
    public Certificate sign(byte[] csrContent) throws RemoteException {
        String tmpName = Long.toString((java.lang.System.currentTimeMillis()));
        try {
            System.out.println(RemoteServer.getClientHost());
            Files.write(Paths.get(tmpName), csrContent);
            boolean result = OpenSSLCliBindings.signRequest(tmpName, authorityCertificateFile, authorityKeyFile, tmpName);
            if(!result) return null;
            Certificate c = CertificateManager.readCertFromFile(tmpName+OpenSSLCliBindings.DEF_CERT_EXTENSION);
            X509Certificate xcert = (X509Certificate)c;
            String cName = xcert.getSubjectDN().getName();
            String commonName = cName.split(",")[0].split("=")[1];
            System.out.println("Certificate done for "+commonName);
            Files.deleteIfExists(Paths.get(tmpName));
            Files.deleteIfExists(Paths.get(tmpName+OpenSSLCliBindings.DEF_CERT_EXTENSION));
            return c;
        } catch(Exception e) {
            e.printStackTrace();
            throw new RemoteException();
        }
    }

    @Override
    public byte[] getCRL() throws RemoteException {//TODO encode
        byte[] crl = {};
        for (Certificate c: certStore) {
            try{
            crl = MessageBuilder.concatBytes(crl,c.getEncoded());
            }catch(CertificateEncodingException ce){
                continue;
            }
        }
        try{
            byte[] sign = SignatureManager.sign(crl,"SHA256withRSA", authKey);
            return MessageBuilder.concatBytes(crl,sign);
        }catch(Exception ex){
            return null;
        }
    }

    
    private void addToCRL(Certificate cert) throws RemoteException {
       if(cert==null)
           return;
       certStore.add(cert);
    }
    
}
