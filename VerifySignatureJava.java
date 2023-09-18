import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class VerifySignatureJava {
    public static boolean verify(String payload, String x_payload_signature, String publicKeyString) throws Exception {
        //Create Public Key
        String publicKeyContent = publicKeyString
                .replace("-----BEGIN PUBLIC KEY-----\n", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyContent);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey =  keyFactory.generatePublic(keySpec);

        // Initialize signature object
        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initVerify(publicKey);

        //Update signature object with 'timestamp.payload'
        String[] parts = x_payload_signature.split(",");
        String timestamp = parts[0].split("=")[1];
        String sigToVerify = parts[1].split("=")[1];
        String updater = timestamp + "." + payload;
        byte[] messageBytes = updater.getBytes();
        signature.update(messageBytes);

        // Verify signature
        byte[] verifyBytes = Base64.getDecoder().decode(sigToVerify);
        return signature.verify(verifyBytes);
    }

        public static void main(String[] args) throws Exception {
        String  x_payload_signature = "t=1693370036,v=Wu5ueKR+Zd1SJROgOY2+UzaLL/MfmpbygRQbIlZfRahUlCrDnSEO1lEr63OzsbUg2M+XAFXsQ" +
                "sHR0T78CLcZR4rGXLefdIFOkdNuLBJa8shO/h/syXGOy69DvqaskQhCaoqeiWFBG20VQpq8PtodneuaawNLAFa8HJSRSBdrc447fO1AO8eTZ7jL1" +
                "0Q+3D5oZzmvYrLNK5UnQM0zyUEYZp6f97n8mw4Ws3SBKOPjMovanNZVb0KG/AerP4Hto5uma+4FkZrY1mDSxHl8Sigu2EAdB/bIhuCtuNBb+EODT" +
                "zuV/r/7Gecr89r8shkz33wjRwadiHyib232CQ/Z1lH9kg==";

        String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqjKM07NnbEN9j19hzfZB\n" +
                "svnv1ooCLnY26YP2wKKap3WQ4tgySVLmEhHOiTu4nBMo2CBdnSUp5js8OW9krGMB\n" +
                "SjmLacO6kZLva6se3Y6Oyo79vlFJ/ESpCBgQRHxqeKL7SR+HgPkwpwkLkJJ8Md22\n" +
                "c4xqGwb1v3AIIynVcADckKTi+TZH7GUnhNye493++oE0lm0rjLIT5lCnrT+rPLJI\n" +
                "a2/Tnh1Nv9iumd0K3XhPE8yOdIJTOkPVpuo3REHfsj1hSHqJZa/r260NuXaQewPz\n" +
                "uRjuAuN8UjYKMuKj9+XBCewiRfli/ULYmityPXDQILLYqar+veOxSaTZPT/1JGtX\n" +
                "XwIDAQAB\n" +
                "-----END PUBLIC KEY-----";

        String payload = "{'appId':'e496f228-f957-4fb2-abb6-98653321cee4','createdAt':'2023-06-02T14:22:22Z','data':{" +
                "'id':1,'first_name':'TTL','last_name':'TEST','email':'dgiametti0@nih.gov','gender':'Male','ip_addres" +
                "s':'55.119.237.50'},'eventId':'cedfa9aa-1775-46eb-8055-11e46235c78f','eventType':'switch-loss-starte" +
                "d','tenantId':'61890020','version':1,'eventSource':'string'}";

        System.out.println(verify(payload, x_payload_signature, publicKey));
    }
}
