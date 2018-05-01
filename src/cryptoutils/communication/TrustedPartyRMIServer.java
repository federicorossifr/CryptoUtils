
package cryptoutils.communication;

import cryptoutils.cipherutils.CertificateManager;
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

public class TrustedPartyRMIServer implements TrustedPartyInterface{
    private Map<String,Certificate> certStore;
    private final String authorityCertificateFile;
    private final String authorityKeyFile;
    
    /**
     * p
     * @param authorityCertificateFile the filename of the authority certificate 
     * @param authorityKeyFile the filename of the authority private key
     */
    public TrustedPartyRMIServer(String authorityCertificateFile,String authorityKeyFile) {
        certStore = loadMap();
        this.authorityCertificateFile= authorityCertificateFile;
        this.authorityKeyFile = authorityKeyFile;
    }
    
    /**
     * Retrieve a Certificate object from the internal storage for the user represented by String user
     * @param user  the requested Certificate's owner
     * @return  the Certificate object (null if  user is not present)
     * @throws RemoteException 
     */
    @Override
    public Certificate getUserCertificate(String user) throws RemoteException {
        try {
            System.out.println(RemoteServer.getClientHost());
        } catch(Exception e) {
            e.printStackTrace();
        }     
        Certificate cert = certStore.get(user);
        return cert;
    }
    
    /**
     * Load the certificate store from file. If file is not found, a new store is created
     * @return the TreeMap representing the certificate store
     */
    private TreeMap<String,Certificate> loadMap()  {
        try(FileInputStream fis = new FileInputStream("cstore.bin");
            ObjectInputStream bis = new ObjectInputStream(fis);) {
            TreeMap<String,Certificate> map = (TreeMap<String,Certificate>) bis.readObject();
            return map;
        } catch(Exception e) {
            e.printStackTrace();
            return new TreeMap<>();
        }
    }
    
    /**
     * Save the current certificate store into a binary file.
     */
    private void backupMap() {
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
    public Certificate register(byte[] csrContent) throws RemoteException {
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
            Certificate curr = certStore.putIfAbsent(commonName, c);
            backupMap();
            Files.deleteIfExists(Paths.get(tmpName));
            Files.deleteIfExists(Paths.get(tmpName+OpenSSLCliBindings.DEF_CERT_EXTENSION));
            if(curr == null)
                return c;
            else {
                System.out.println("Certificate for "+commonName+"already exists...");
                Files.deleteIfExists(Paths.get(tmpName+OpenSSLCliBindings.DEF_CERT_EXTENSION));
                return null;
            }
        } catch(Exception e) {
            e.printStackTrace();
            throw new RemoteException();
        }
    }
    
}
