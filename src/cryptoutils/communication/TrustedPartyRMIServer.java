
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

public class TrustedPartyRMIServer implements TrustedPartyInterface{
    private Map<String,Certificate> certStore;
    private final String authorityCertificateFile;
    private final String authorityKeyFile;
    public TrustedPartyRMIServer(String authorityCertificateFile,String authorityKeyFile) {
        certStore = loadMap();
        this.authorityCertificateFile= authorityCertificateFile;
        this.authorityKeyFile = authorityKeyFile;
    }
    @Override
    public Certificate getUserCertificate(String user) throws RemoteException {
        Certificate cert = certStore.get(user);
        return cert;
    }
    
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
    
    private void backupMap() {
        try(FileOutputStream fos = new FileOutputStream("cstore.bin");
            ObjectOutputStream bos = new ObjectOutputStream(fos);)
        {
            bos.writeObject(certStore);
        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public Certificate register(byte[] csrContent) throws RemoteException {
        String tmpName = Long.toString((java.lang.System.currentTimeMillis()));
        try {
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
            if(curr == null)
                return c;
            else {
                System.out.println("Certificate for "+commonName+"already exists...");
                Files.deleteIfExists(Paths.get(tmpName+OpenSSLCliBindings.DEF_CERT_EXTENSION));
                return curr;
            }
        } catch(Exception e) {
            e.printStackTrace();
            throw new RemoteException();
        }
    }
    
}
