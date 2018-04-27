package openssl;
public class OpenSSLCliBindings {
    private final static String WHITELIST_REGEX = "[^a-zA-Z0-9 ]";
    private final static String GEN_CSR_CMD = "openssl req -new -key $pkey$ -out $csrout$ -subj '/C=$CountryName$/ST=$State$/L=$LocalityName$/O=$OrganizationName$/CN=$CommonName$\'";
    private static String escapeString(String s) {
        return s.replaceAll(WHITELIST_REGEX, "");
    }
    public static void generateCSR(String pkeyFile,String outFile,String countryName,String state,String localityName,String organization,String commonName)  {
        countryName = escapeString(countryName);
        state = escapeString(state);
        localityName = escapeString(localityName);
        organization = escapeString(organization);
        commonName = escapeString(commonName);
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
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
}
