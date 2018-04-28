package cryptoutils.openssl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * This class provides methods to invoke openssl library commands if globally available on the running machine.
 * @author Federico Rossi
 */
public class OpenSSLCliBindings {
    public final static String DEF_CERT_EXTENSION = ".cer";
    private final static String WHITELIST_REGEX = "[^a-zA-Z0-9 ]";
    private final static String GEN_CSR_CMD = "openssl req -new -key $pkey$ -out $csrout$ -subj \"/C=$CountryName$/ST=$State$/L=$LocalityName$/O=$OrganizationName$/CN=$CommonName$\"";
    private final static String GEN_PRI_KEY = "openssl genrsa -out tmp 2048";
    private final static String CONVERT_KEY_PKCS8 = "openssl pkcs8 -topk8 -inform pem -in tmp -outform pem -nocrypt -out $pkeyout$";
    private final static String SIGN_REQ_CMD = "openssl x509 -req -days 365 -in $csrfile$ -CA $authcert$ -CAcreateserial -CAkey $authkey$ -out $certout$ -sha256";
    private final static String VERIFY_CSR = "openssl req -verify -in $csrfile$ -noout";
    private final static String VERIFY_OK_STATUS = "verify OK";
    
    /**
     * Escape a string using the WHITELIST_REGEX regular expression, without removing whiteSpaces
     * @param s
     * @return 
     */
    private static String escapeString(String s) {
        return escapeString(s,false);
    }
    
    /**
     * Escape a string using the WHITELIST_REGEX regular expression
     * @param s             the string to be escaped
     * @param noWhitespaces when TRUE indicates that whitespaces must be escaped from string
     * @return              escaped String
     */
    private static String escapeString(String s,boolean noWhitespaces) {
        String tmp = s.replaceAll(WHITELIST_REGEX, "");
        if(noWhitespaces)
            tmp=tmp.replaceAll(" ", "");
        return tmp;
    }
    
    /**
     * Gets the String object representing the process error stream output
     * @param p the process to take from the output
     * @return  String representing the output of the process
     * @throws IOException 
     */
    private static String getProcessOutput(Process p) throws IOException {
        StringBuilder sbf = new StringBuilder();
        BufferedReader bf = new BufferedReader(new InputStreamReader(p.getErrorStream()));
        String line="";
        while((line = bf.readLine())!=null) sbf.append(line);
        return sbf.toString();
    }
    
    /**
     * Generates a certificate signing request using standard openssl library commands
     * @param pkeyFile      the filename of the private key file to sign csr
     * @param outFile       the filename of the desired output file
     * @param countryName   the country name of the subject
     * @param state         the state name of the subject
     * @param localityName  the locality name of the subject
     * @param organization  the organization name of the subject
     * @param commonName    the common name of the subject
     * @return              true if everything goes fine
     */
    public static boolean generateCSR(String pkeyFile,String outFile,String countryName,String state,String localityName,String organization,String commonName)  {
        countryName = escapeString(countryName);
        state = escapeString(state);
        localityName = escapeString(localityName);
        organization = escapeString(organization);
        commonName = escapeString(commonName);
        pkeyFile = escapeString(pkeyFile,true);
        outFile = escapeString(outFile,true);
        String cmd = GEN_CSR_CMD;
        cmd=cmd.replace("$CountryName$", countryName);
        cmd=cmd.replace("$State$", state);
        cmd=cmd.replace("$LocalityName$", localityName);
        cmd=cmd.replace("$OrganizationName$", organization);
        cmd=cmd.replace("$CommonName$", commonName);
        cmd=cmd.replace("$pkey$",pkeyFile);
        cmd=cmd.replace("$csrout$", outFile);
        System.out.println(cmd);
        
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            p.waitFor();
            return Files.exists(Paths.get(outFile));
        } catch(Exception e) {
            e.printStackTrace();
            return false;
        }
    }
   
    /**
     * Generates a private key file in the PKCS8 format using standard opnssl library commands.
     * @param pkeyOut   desired output file name
     * @return          true if everything goes fine
     */
    public static boolean generatePrivateKey(String pkeyOut) {
        pkeyOut = escapeString(pkeyOut,true);
        String genPKCS8 = CONVERT_KEY_PKCS8;
        genPKCS8=genPKCS8.replace("$pkeyout$",pkeyOut);
        System.out.println(genPKCS8);
        try {
            System.out.println(GEN_PRI_KEY);            
            Process p = Runtime.getRuntime().exec(GEN_PRI_KEY);
            p.waitFor();
            System.out.println(GEN_PRI_KEY);            
            p = Runtime.getRuntime().exec(genPKCS8);
            p.waitFor();
            return Files.exists(Paths.get(pkeyOut));
        } catch(Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * Signs a csr request using the certification authority certificate and private key
     * @param requestFile   filename for the csr request
     * @param certFile      filename for the auth certificate
     * @param authKeyFile   filename for the auth private key
     * @param outfile       desired output filename (the certificate output is composed by output + DEF_CERT_EXTENSION
     * @return              true if everything goes fine
     */
    public static boolean signRequest(String requestFile,String certFile,String authKeyFile,String outfile) {
        requestFile = escapeString(requestFile,true);
        certFile = escapeString(certFile,true);
        authKeyFile = escapeString(authKeyFile,true);
        outfile = escapeString(outfile,true);
        String verifyCmd = VERIFY_CSR;
        String signCmd = SIGN_REQ_CMD;
        verifyCmd=verifyCmd.replace("$csrfile$", requestFile);
        signCmd=signCmd.replace("$csrfile$", requestFile);
        signCmd=signCmd.replace("$authcert$", certFile);
        signCmd=signCmd.replace("$authkey$", authKeyFile);
        signCmd=signCmd.replace("$certout$", outfile+DEF_CERT_EXTENSION);
        try {
            System.out.println(verifyCmd);
            Process p = Runtime.getRuntime().exec(verifyCmd);
            p.waitFor();
            String res = getProcessOutput(p);
            System.out.println(res);
            if(res == null || !res.equals(VERIFY_OK_STATUS)) return false;
            System.out.println(signCmd);
            p = Runtime.getRuntime().exec(signCmd);
            p.waitFor();
            return Files.exists(Paths.get(outfile));
        } catch(Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
