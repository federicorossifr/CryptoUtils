package cryptoutils.communication;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.cert.Certificate;

public interface TrustedPartyInterface extends Remote {
    /**
     * 
     * @param user
     * @return
     * @throws RemoteException 
     */
    Certificate getUserCertificate(String user) throws RemoteException;
    /**
     * 
     * @param csrContent
     * @return
     * @throws RemoteException 
     */
    Certificate register(byte[] csrContent) throws RemoteException;
}
