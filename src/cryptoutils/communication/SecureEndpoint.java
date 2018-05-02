package cryptoutils.communication;

import cryptoutils.cipherutils.CryptoManager;
import cryptoutils.messagebuilder.MessageBuilder;
import cryptoutils.hashutils.HashManager;
import java.io.*;
import java.time.Instant;
import java.util.Random;

public class SecureEndpoint {
    public final static String AUTH_ALG = "HmacSHA256";
    private static final int AUTH_MAC_SIZE = 256/8;
    private static final long TIME_TH = 1000;
    public static boolean secureSend(byte[] data,ObjectOutputStream ds,byte[] encKey, byte[] authKey) {
        try{
            System.out.println("[SECURE SEND - "+Thread.currentThread().getName()+"]");
            byte[] timestampedMessage = MessageBuilder.insertTimestamp(data);
            byte[] hashedMessage = MessageBuilder.insertMAC(timestampedMessage,AUTH_ALG,authKey);
            byte[] encryptedMessage = CryptoManager.encryptCBC(hashedMessage, encKey, new Random().nextInt()); 
            System.out.println("[SEND - "+Thread.currentThread().getName()+"]: SENDING ENCRYPTED MESSAGE");                        
            ds.writeObject(encryptedMessage);
            ds.flush();
            return true;
        } catch(Exception e) {
            System.err.println("[SEND - "+Thread.currentThread().getName()+"]: "+e.getMessage());
            System.exit(-1);            
            return false;
        }              
    }
    
    public static byte[] secureReceive(ObjectInputStream di,byte[] encKey, byte[] authKey) {
        try {
            byte[] buffer = (byte []) di.readObject();
            byte[] decryptedMessage = CryptoManager.decryptCBC(buffer, encKey);
            byte[] messageHash = MessageBuilder.extractHash(decryptedMessage, AUTH_MAC_SIZE);  
            Instant timeStamp = MessageBuilder.getTimestamp(decryptedMessage,decryptedMessage.length-AUTH_MAC_SIZE-8);
            byte[] timestampedMessage = MessageBuilder.extractFirstBytes(decryptedMessage, decryptedMessage.length-AUTH_MAC_SIZE);
            byte[] plainText = MessageBuilder.extractFirstBytes(timestampedMessage,timestampedMessage.length-8);
            boolean verified = (HashManager.compareMAC(timestampedMessage, messageHash, authKey, AUTH_ALG) && verifyTimestamp(timeStamp));    
            return (verified)?plainText:null;
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
