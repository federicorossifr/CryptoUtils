package cryptoutils.communication;

import java.rmi.*;

public interface TrustedPartyInterface extends Remote {
    /**
     * @param nonce
     * @return
     * @throws RemoteException 
     */ 
    byte[] getCRL(byte[] nonce) throws RemoteException;  

}
