package messagebuilder;

import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import hashutils.HashManager;

public class MessageBuilder {
    public static byte[] concatBytes(byte[] a,byte[] b) {
        byte[] result = Arrays.copyOf(a, a.length+b.length);
        System.arraycopy(b, 0, result, a.length, b.length);        
        return result;
    }
    
    public static byte[] toByteArray(int i) {
        return ByteBuffer.allocate(4).putInt(i).array();
    }
    
    public static byte[] toByteArray(long l) {
        return ByteBuffer.allocate(8).putLong(l).array();
    }    
    
    public static long toLong(byte[] b) {
        return ByteBuffer.wrap(b).getLong();
    }
    
    public static int toInt(byte[] b) {
        return ByteBuffer.wrap(b).getInt();
    }    
    
    public static byte[] extractFirstBytes(byte[] msg,int n) {
        return Arrays.copyOfRange(msg, 0, n);
    }
    
    public static byte[] extractLastBytes(byte[] msg,int n) {
        return Arrays.copyOfRange(msg,msg.length-n , msg.length);
    }    
    
    public static byte[] insertHash(byte[] msg,String hashAlg) throws NoSuchAlgorithmException {
        byte[] hash = HashManager.doHash(msg, hashAlg);
        return concatBytes(hash, msg);
    }
    
    public static byte[] insertMAC(byte[] msg,String macAlg,String key) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] mac = HashManager.doMAC(msg, macAlg, key);
        return concatBytes(msg, mac);
    }
    
    public static byte[] extractHash(byte[] msg,int hashSize,int pos) { //WORKS THE SAME FOR MAC
        return Arrays.copyOfRange(msg, pos, pos+hashSize);
    }
    
    public static byte[] extractHash(byte[] msg,int hashSize) { //WORKS THE SAME FOR MAC
        return extractHash(msg,hashSize,msg.length-hashSize);
    }
    
    public static byte[] insertNonce(byte[] msg,int nonce) {
        byte[] nonceBytes = ByteBuffer.allocate(4).putInt(nonce).array();
        return concatBytes(msg, nonceBytes);
    }
    
    public static int extractNonce(byte[] msg,int pos) {
        byte[] nonceBytes = Arrays.copyOfRange(msg, pos, pos+4);
        return ByteBuffer.wrap(nonceBytes).getInt();
    }
    
    public static int extractNonce(byte[] msg) {
        return extractNonce(msg,msg.length-4);
    }
    
    
    public static void main(String[] args) {

    }
    
}
