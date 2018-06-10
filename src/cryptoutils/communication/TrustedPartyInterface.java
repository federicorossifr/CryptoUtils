package cryptoutils.communication;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface TrustedPartyInterface extends Remote {
    /**
     * @return
     * @throws RemoteException 
     */ 
    byte[] getCRL(byte[] nonce) throws RemoteException;  

}
