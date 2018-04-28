package cryptoutils.messagebuilder;

import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import cryptoutils.hashutils.HashManager;

public class MessageBuilder {
    /**
     * Concatenates the two byte[] objects passed as parametres
     * @param a
     * @param b
     * @return the byte[] object representing the concatenation
     */
    public static byte[] concatBytes(byte[] a,byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length+b.length);
        System.arraycopy(b, 0, result, a.length, b.length);        
        return result;
    }
    
    /**
     * Converts an integer into a byte[] object
     * @param i the integer
     * @return the byte[] object
     */
    public static byte[] toByteArray(int i) {
        return ByteBuffer.allocate(4).putInt(i).array();
    }
    /**
     * Converts a long into a byte[] object
     * @param l the long
     * @return the byte[] object
     */
    
    public static byte[] toByteArray(long l) {
        return ByteBuffer.allocate(8).putLong(l).array();
    }    
    
    /**
     * Converts a byte[] object into a long
     * @param b the byte[] object
     * @return the long
     */
    public static long toLong(byte[] b) {
        return ByteBuffer.wrap(b).getLong();
    }
    
    /**
     * Converts a byte[] objct into an int
     * @param b the byte[] object
     * @return the int
     */
    public static int toInt(byte[] b) {
        return ByteBuffer.wrap(b).getInt();
    }    
    
    /**
     * Exstract the n first bytes from the byte[] object msg
     * @param msg   
     * @param n
     * @return 
     */
    public static byte[] extractFirstBytes(byte[] msg,int n) {
        return Arrays.copyOfRange(msg, 0, n);
    }
    
    /**
     * Extracts the n last bytes from the byte[] object msg
     * @param msg
     * @param n
     * @return 
     */
    public static byte[] extractLastBytes(byte[] msg,int n) {
        return Arrays.copyOfRange(msg,msg.length-n , msg.length);
    }    
    
    /**
     * Computes the msg hash and concatenate it to the beginning
     * @param msg
     * @param hashAlg the hash algorithm to use
     * @return
     * @throws NoSuchAlgorithmException 
     */
    public static byte[] insertHash(byte[] msg,String hashAlg) throws NoSuchAlgorithmException {
        byte[] hash = HashManager.doHash(msg, hashAlg);
        return concatBytes(hash, msg);
    }
    
    /**
     * Computes the MAC msg and concatenate to the end
     * @param msg
     * @param macAlg the algorithm to use
     * @param key the secret key to use
     * @return  
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException 
     */
    public static byte[] insertMAC(byte[] msg,String macAlg,String key) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] mac = HashManager.doMAC(msg, macAlg, key);
        return concatBytes(msg, mac);
    }
    
    /**
     * Extracts an hash of size hashSize starting from position pos
     * @param msg
     * @param hashSize
     * @param pos
     * @return 
     */
    public static byte[] extractHash(byte[] msg,int hashSize,int pos) { //WORKS THE SAME FOR MAC
        return Arrays.copyOfRange(msg, pos, pos+hashSize);
    }
    
    /**
     * Extracts an hash/MAC of size hashSize from the end of the msg
     * @param msg
     * @param hashSize
     * @return 
     */
    public static byte[] extractHash(byte[] msg,int hashSize) { //WORKS THE SAME FOR MAC
        return extractHash(msg,hashSize,msg.length-hashSize);
    }
    
    /**
     * Inserts an integer nonce to the beginning of the message
     * @param msg
     * @param nonce
     * @return 
     */
    public static byte[] insertNonce(byte[] msg,int nonce) {
        byte[] nonceBytes = ByteBuffer.allocate(4).putInt(nonce).array();
        return concatBytes(msg, nonceBytes);
    }
    
    /**
     * Extracts a nonce integer from position pos
     * @param msg
     * @param pos
     * @return 
     */
    public static int extractNonce(byte[] msg,int pos) {
        byte[] nonceBytes = Arrays.copyOfRange(msg, pos, pos+4);
        return ByteBuffer.wrap(nonceBytes).getInt();
    }
    
    /**
     * Extracts am integer nonce from the end of msg
     * @param msg
     * @return 
     */
    public static int extractNonce(byte[] msg) {
        return extractNonce(msg,msg.length-4);
    }
}
