package openssl;

import java.nio.file.Files;
import java.nio.file.Paths;

public class OpenSSLCliBindings {
    private final static String WHITELIST_REGEX = "[^a-zA-Z0-9 ]";
    private final static String GEN_CSR_CMD = "openssl req -new -key $pkey$ -out $csrout$ -subj \"/C=$CountryName$/ST=$State$/L=$LocalityName$/O=$OrganizationName$/CN=$CommonName$\"";
    private final static String GEN_PRI_KEY = "openssl genrsa -out tmp 2048";
    private final static String CONVERT_KEY_PKCS8 = "openssl pkcs8 -topk8 -inform pem -in tmp -outform pem -nocrypt -out $pkeyout$";
    private final static String SIGN_REQ_CMD = "openssl x509 -req -days 365 -in $csrfile$ -CA $authcert$ -CAcreateserial -CAkey $authkey$ -out $certout$ -sha256";
    private static String escapeString(String s) {
        return s.replaceAll(WHITELIST_REGEX, "");
    }
    public static boolean generateCSR(String pkeyFile,String outFile,String countryName,String state,String localityName,String organization,String commonName)  {
        countryName = escapeString(countryName);
        state = escapeString(state);
        localityName = escapeString(localityName);
        organization = escapeString(organization);
        commonName = escapeString(commonName);
        pkeyFile = escapeString(pkeyFile);
        outFile = escapeString(outFile);
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
   
    public static boolean generatePrivateKey(String pkeyOut) {
        pkeyOut = escapeString(pkeyOut);
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
    
    public static boolean signRequest(String requestFile,String certFile) {
        return true;
    }
}
