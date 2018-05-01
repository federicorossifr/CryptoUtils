package cryptoutils.communication;

import cryptoutils.cipherutils.CryptoManager;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import javax.crypto.Mac;
import cryptoutils.messagebuilder.MessageBuilder;
import cryptoutils.hashutils.HashManager;
import java.security.SecureRandom;

public class SecureEndpoint {
    private final byte[] encKey;
    private final String authKey;
    private final String authAlg;
    private int sequenceCounter = 0;
    private int authMACSize;
    
    public SecureEndpoint(String encKey,String authKey,String authAlg) {
        this.authKey = authKey;
        this.authAlg = authAlg;
        this.encKey = encKey.getBytes();
        try {
            authMACSize = (Mac.getInstance(authAlg)).getMacLength();
        } catch (Exception ex) {
            System.err.println("[CONSTRUCTOR - "+Thread.currentThread().getName()+"]: "+ex.getMessage());
            System.exit(-1);
        }
    }
    
    protected boolean secureSend(byte[] data,DataInputStream di,DataOutputStream ds) {
        try{
            System.out.println("[SEND - "+Thread.currentThread().getName()+"]: RECEIVING NONCE");
            int nonce = di.readInt();
            byte[] noncedMessage = MessageBuilder.insertNonce(data, nonce);
            byte[] hashedMessage = MessageBuilder.insertMAC(noncedMessage,authKey,authAlg);
            byte[] encryptedMesage = CryptoManager.encryptCBC(hashedMessage, encKey, ++sequenceCounter);
            System.out.println("[SEND - "+Thread.currentThread().getName()+"]: SENDING SIZE (bytes) "+encryptedMesage.length);            
            ds.writeInt(encryptedMesage.length);
            System.out.println("[SEND - "+Thread.currentThread().getName()+"]: SENDING PAYLOAD");                        
            ds.write(encryptedMesage);
            ds.flush();
            return true;
        } catch(Exception e) {
            System.err.println("[SEND - "+Thread.currentThread().getName()+"]: "+e.getMessage());
            System.exit(-1);            
            return false;
        }              
    }
    
    protected byte[] secureReceive(DataInputStream di,DataOutputStream ds) {
        try {
            int nonce = (new SecureRandom()).nextInt();
            ds.writeInt(nonce); ds.flush();
            int len = di.readInt();
            if(len > 0) {
                byte[] buffer = new byte[len];
                long read = di.read(buffer);
                if(read != len) throw new Exception("Expected: "+len+ " received: "+read);
                byte[] decryptedMessage = CryptoManager.decryptCBC(buffer, encKey);
                byte[] messageHash = MessageBuilder.extractHash(decryptedMessage, authMACSize);
                int messageNonce = MessageBuilder.extractNonce(decryptedMessage, decryptedMessage.length-authMACSize-4);
                byte[] noncedMessage = MessageBuilder.extractFirstBytes(decryptedMessage, decryptedMessage.length-authMACSize);
                byte[] plainText = MessageBuilder.extractFirstBytes(noncedMessage,noncedMessage.length-4);
                boolean verified = (HashManager.compareMAC(noncedMessage, messageHash, authKey, authAlg) && messageNonce == nonce);    
                return (verified)?plainText:null;
            } else {
                return null;
            }
        } catch(Exception e) {
            System.err.println("[RECEIVE- "+Thread.currentThread().getName()+"]: "+e.getMessage());
            System.exit(-1);            
            return null;
        }        
    }
}
