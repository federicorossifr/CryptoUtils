package cryptoutils.communication;

import cryptoutils.cipherutils.CryptoManager;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import cryptoutils.messagebuilder.MessageBuilder;
import cryptoutils.hashutils.HashManager;
import java.time.Instant;
import java.util.Random;

public class SecureEndpoint {
    private final static String AUTH_ALG = "HmacSHA256";
    private static final int AUTH_MAC_SIZE = 256/8;
    private static final long TIME_TH = 1000;
    public static boolean secureSend(byte[] data,DataOutputStream ds,byte[] encKey, String authKey) {
        try{
            System.out.println("[SECURE SEND - "+Thread.currentThread().getName()+"]");
            byte[] timestampedMessage = MessageBuilder.insertTimestamp(data);
            byte[] hashedMessage = MessageBuilder.insertMAC(timestampedMessage,authKey,AUTH_ALG);
            byte[] encryptedMessage = CryptoManager.encryptCBC(hashedMessage, encKey, new Random().nextInt()); 
            System.out.println("[SEND - "+Thread.currentThread().getName()+"]: SENDING SIZE (bytes) "+encryptedMessage.length);            
            ds.writeInt(encryptedMessage.length);
            System.out.println("[SEND - "+Thread.currentThread().getName()+"]: SENDING PAYLOAD");                        
            ds.write(encryptedMessage);
            ds.flush();
            return true;
        } catch(Exception e) {
            System.err.println("[SEND - "+Thread.currentThread().getName()+"]: "+e.getMessage());
            System.exit(-1);            
            return false;
        }              
    }
    
    public static byte[] secureReceive(DataInputStream di,byte[] encKey, String authKey) {
        try {
            int len = di.readInt();
            if(len > 0) {
                byte[] buffer = new byte[len];
                long read = di.read(buffer);
                if(read != len) throw new Exception("Expected: "+len+ " received: "+read);
                byte[] decryptedMessage = CryptoManager.decryptCBC(buffer, encKey);
                byte[] messageHash = MessageBuilder.extractHash(decryptedMessage, AUTH_MAC_SIZE);  
                Instant timeStamp = MessageBuilder.getTimestamp(decryptedMessage,decryptedMessage.length-AUTH_MAC_SIZE-8);
                byte[] timestampedMessage = MessageBuilder.extractFirstBytes(decryptedMessage, decryptedMessage.length-AUTH_MAC_SIZE);
                byte[] plainText = MessageBuilder.extractFirstBytes(timestampedMessage,timestampedMessage.length-8);
                boolean verified = (HashManager.compareMAC(timestampedMessage, messageHash, authKey, AUTH_ALG) && verifyTimestamp(timeStamp));    
                return (verified)?plainText:null;
            } else {
                return null;
            }
        } catch(Exception e) {
            System.err.println("[RECEIVE- "+Thread.currentThread().getName()+"]: "+e.getMessage());
            e.printStackTrace();
            System.exit(-1);            
            return null;
        }        
    }
    private static boolean verifyTimestamp(Instant timeStamp){
        Instant now = Instant.now();
        return !(timeStamp.isAfter(now.plusMillis(TIME_TH))||timeStamp.isBefore(now.minusMillis(TIME_TH)));    
    }
}
