package cryptoutils.communication;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.cert.Certificate;

public interface TrustedPartyInterface extends Remote {
    Certificate getUserCertificate(String user) throws RemoteException;
    Certificate register(byte[] csrContent) throws RemoteException;
}
