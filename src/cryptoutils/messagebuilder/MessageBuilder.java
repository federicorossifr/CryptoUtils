package cryptoutils.messagebuilder;

import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import cryptoutils.hashutils.HashManager;
import java.time.Instant;

public class MessageBuilder {
    /**
     * Concatenates the two byte[] objects passed as parametres
     * @param arrays variadic arguments containing all the byte[] objects to be concatenated
     * @return the byte[] object representing the concatenation
     */
    public static byte[] concatBytes(byte[]... arrays) {
        int totalSize = 0;
        int currentSize = 0;
        for(int i = 0; i < arrays.length; ++i) {
            totalSize+=arrays[i].length;
        }
        byte[] result = new byte[totalSize];
        for(int i = 0; i < arrays.length; ++i) {
            System.arraycopy(arrays[i], 0, result, currentSize, arrays[i].length);        
            currentSize+=arrays[i].length;
        }
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
    
    
    public static byte[] extractRangeBytes(byte[] msg,int from,int to) {
        return Arrays.copyOfRange(msg,from,to);
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
    public static byte[] insertMAC(byte[] msg,String macAlg,byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] mac = HashManager.doMAC(msg, key, macAlg);
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
     * Inserts a timestamp to be used as nonce
     * @param msg the message to concatenate with timestamp
     * @return the new timestamped message
     */
    public static byte[] insertTimestamp(byte[] msg) {
        byte[] timestampBytes = toByteArray(Instant.now().toEpochMilli());
        return concatBytes(msg,timestampBytes);
    }
    
    /**
     * Exta
     */
    public static Instant getTimestamp(byte[] msg,int pos) {
        byte[] timestampBytes = extractRangeBytes(msg,pos ,pos+8);
        return Instant.ofEpochMilli(toLong(timestampBytes));
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
