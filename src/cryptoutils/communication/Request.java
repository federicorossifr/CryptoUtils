package cryptoutils.communication;

import cryptoutils.cipherutils.*;
import cryptoutils.messagebuilder.MessageBuilder;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.*;
import java.time.Instant;
import javax.crypto.*;

/**
 * This class represents a handshake Request from the issuer to the recipient. 
 * Certificate is the issuer certificate to prove its identity (signed by ttp)
 * SecretKey is the shared secret key (encrypted by means of recipient public key)
 * Challenge nonce is used to prevent reply attacks (encrypted by means of recipient public key)
 * Signature is the digital signature of the request to prevent tampering
 */
public class Request {
    private final static long SLEEK_TH = 60*1000;
    private final String issuer;
    private final String recipient;
    private final Certificate certificate;
    private byte[] secretKey;
    private byte[] timestamp = null;
    private byte[] signature = null;
    private final static int NUM_FIELDS = 6;
    
    /**
     * Decode the byte[] array enc into a Request object
     * @param enc the byte array
     * @return the request object
     * @throws CertificateException 
     */
    private static Request fromEncodedRequest(byte[] enc) throws CertificateException {
        int sizeBuf; int pointer = 0; byte[][] fields = new byte[NUM_FIELDS][];
        for(int i = 0; i < NUM_FIELDS && pointer < enc.length; ++i) {
            byte[] lengthBytes = MessageBuilder.extractRangeBytes(enc, pointer,pointer+4); 
            sizeBuf = MessageBuilder.toInt(lengthBytes); pointer+= 4;
            byte[] contentBytes = MessageBuilder.extractRangeBytes(enc, pointer, pointer+sizeBuf); 
            pointer+=sizeBuf;            
            fields[i] = contentBytes;
        }
        if(pointer != enc.length) throw new CertificateException();
        String issuer = new String(fields[0]);
        String recipient = new String(fields[1]);
        CertificateFactory certFactory =  CertificateFactory.getInstance("X.509");
        InputStream is = new ByteArrayInputStream(fields[2]);
        Certificate certificate = certFactory.generateCertificate(is);
        byte[] secretKey = fields[3];
        byte[]challengeNonce = fields[4];
        byte[] signature = fields[5];
        return new Request(issuer,recipient,certificate,challengeNonce,signature,secretKey);
    }
    
    /**
     * Decode an encrypted request contained into byte[] object by means of PrivateKey key
     * @param enc the encrypted request
     * @param key the private key
     * @return the Request object
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws CertificateException 
     */
    public static Request fromEncryptedRequest(byte[] enc,PrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, CertificateException {
        Request r = fromEncodedRequest(enc);
        r.secretKey = CryptoManager.decryptRSA(r.secretKey, key);
        return r;
    }
    
    /**
     * Issuer constructor
     * @param issuer
     * @param recipient
     * @param certificate
     * @param secretKey 
     */
    public Request(String issuer,String recipient,Certificate certificate,byte[] secretKey) {
        this.certificate = certificate;
        this.recipient = recipient;
        this.issuer = issuer;
        this.secretKey = secretKey;
        this.timestamp = MessageBuilder.toByteArray(Instant.now().toEpochMilli());
    }
    
    /**
     * Private constructor used only by the decoding operations
     * @param issuer
     * @param recipient
     * @param certificate
     * @param challengeNonce
     * @param signature
     * @param secretKey 
     */
    private Request(String issuer,String recipient,Certificate certificate,byte[] challengeNonce,byte[] signature,byte[] secretKey) {
        this.certificate = certificate;
        this.recipient = recipient;
        this.issuer = issuer;
        this.timestamp = challengeNonce;
        this.signature = signature;
        this.secretKey = secretKey;
    }    
    
    /**
     * Signs the request by means of the issuer private key
     * @param key
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException 
     */
    public void sign(PrivateKey key) throws CertificateEncodingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] data = MessageBuilder.concatBytes(issuer.getBytes(),recipient.getBytes(),certificate.getEncoded(),secretKey,timestamp);
        signature = SignatureManager.sign(data, "SHA256withRSA", key);
    }
    
    /**
     * Verifies the signature using the certificate embedded into the request
     * @return 
     */
    public boolean verifySignature() {
        try {
            byte[] data = MessageBuilder.concatBytes(issuer.getBytes(),recipient.getBytes(),certificate.getEncoded(),secretKey,timestamp);
            return SignatureManager.verify(data, signature, "SHA256withRSA",certificate);
        } catch(Exception e) {
            return false;
        }
    }
    
    /**
     * Computes a secure random challenge and returns its value
     * @return 
     */
    public int setRandomChallenge() {
        SecureRandom sr = new SecureRandom();
        byte[] bytes = new byte[4];
        sr.nextBytes(bytes);
        timestamp = bytes;
        return MessageBuilder.toInt(timestamp);
    }
    
    /**
     * Get the encoded bytes of the certificate. The byte[] representation has the format < field_length,field_content >
     * @return
     * @throws CertificateEncodingException 
     */
    private byte[] getEncoded() throws CertificateEncodingException {
        byte[] iB = issuer.getBytes(); byte[] iL = MessageBuilder.toByteArray(iB.length);
        byte[] rB = recipient.getBytes(); byte[] rL = MessageBuilder.toByteArray(rB.length);
        byte[] skB = secretKey; byte[] skL = MessageBuilder.toByteArray(secretKey.length);
        byte[] cB = certificate.getEncoded(); byte[] cL = MessageBuilder.toByteArray(cB.length);
        byte[] nB = timestamp; byte[] nL = MessageBuilder.toByteArray(nB.length);
        byte[] sB = signature; byte[] sL = MessageBuilder.toByteArray(sB.length); 
        byte[] out = MessageBuilder.concatBytes(iL,iB,rL,rB,cL,cB,skL,skB,nL,nB,sL,sB);
        return out;
    }
    
    /**
     * Computes the encrypted version of the request and returns the encoded one. Only secret key and challenge nonce are encrypted
     * @param recipientPublicKey
     * @return
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public byte[] getEncrypted(PublicKey recipientPublicKey) throws CertificateEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if(signature == null || timestamp == null) return null;
        System.out.println("SCRET KEY LENGTH " + secretKey.length);
        secretKey = CryptoManager.encryptRSA(secretKey, recipientPublicKey);
        byte[] encoded = getEncoded();
        return encoded;
    }
    
    /**
     * Return the secretKey (plain)
     * @return 
     */
    public byte[] getSecretKey() {
        return secretKey;
    }
    
    /**
     * Get the request issuer name
     * @return 
     */
    public String getIssuer() {
        return issuer;
    }
    
    /**
     * Get the recipient name
     * @return 
     */
    public String getRecipient() {
        return recipient;
    }
    
    /**
     * Verifies the certificate using the releasing authority certificate
     * @param authority
     * @return 
     */
    public boolean verifyCertificate(Certificate authority) {
        X509Certificate xc = (X509Certificate)certificate;
        return CertificateManager.verifyCertificate(xc, authority);
    }
    
    /**
     * Gets the issuing authority of the certificate
     * @return 
     */
    public String getCertificateIssuer() {
        X509Certificate xc = ((X509Certificate)certificate);
        return xc.getIssuerDN().toString();
    }
    
    /**
     * Gets the issuer public key from the certificate
     * @return 
     */
    public PublicKey getPublicKey(){
        return certificate.getPublicKey();
    }
    
    /**
     * Gets the subject of the certificate (it must be equals to the issuer)
     * @return 
     */
    public String getCertificateSubject() {
        X509Certificate xc = ((X509Certificate)certificate);
        return xc.getSubjectDN().toString();
    }
    
    
    /**
     * Get the challenge nonce
     * @return 
     */
    public Instant getTimestamp() {
        return MessageBuilder.getTimestamp(timestamp, 0);
    }
    
    public boolean verify(Certificate authority,String expectedSubject) {
        System.out.println("=======");
        boolean verified = true;
        verified&=(verifySignature() && verifyCertificate(authority));
        System.out.println(verified);
        String subject = CertificateManager.getCertificateSubjectName((X509Certificate)certificate);
        if(subject == null) return false;
        if(expectedSubject != null)
            verified&=(expectedSubject.equals(subject) && issuer.equals(expectedSubject));
        System.out.println(verified);        
        verified&=(subject.equals(issuer));
        System.out.println(verified);        
        Instant now = Instant.now();
        System.out.println(now.toEpochMilli());
        System.out.println(getTimestamp().toEpochMilli());
        verified&=!(getTimestamp().isAfter(now.plusMillis(SLEEK_TH))||getTimestamp().isBefore(now.minusMillis(SLEEK_TH)));
        System.out.println(verified);  
        System.out.println("=======");        
        return verified;
    }
    public Certificate getCertificate(){
        return certificate;
    }
}
