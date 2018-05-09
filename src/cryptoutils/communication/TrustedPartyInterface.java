package cryptoutils.communication;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.util.ArrayList;

public interface TrustedPartyInterface extends Remote {

    /**
     * 
     * @param csrContent
     * @return
     * @throws RemoteException 
     */
    Certificate sign(byte[] csrContent) throws RemoteException;
    /**
     * 
     * @param cert
     * @return
     * @throws RemoteException 
     */
    byte[] getCRL( Certificate cert) throws RemoteException;

}
