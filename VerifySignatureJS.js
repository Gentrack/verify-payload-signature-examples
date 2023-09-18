const verifySignatureJS = (signature, publicKey, payload) => {
    const parts = signature.split(","); // x-payload-signature: t=[number],v=[signature]
    const timestamp = parts[0];
    const digest = parts[1];
    const verifier = crypto.createVerify("sha512");
    verifier.update(timestamp.split("=")[1] + ".");
    verifier.update(payload);
    const sigToVerify = digest.split("=")[1];
    const result = verifier.verify(publicKey, sigToVerify, "base64");
    console.log(result); // boolean
};

const x_payload_signature = "t=1693370036,v=Wu5ueKR+Zd1SJROgOY2+UzaLL/MfmpbygRQbIlZfRahUlCrDnSEO1lEr63OzsbUg2M+XAFXsQ" +
    "sHR0T78CLcZR4rGXLefdIFOkdNuLBJa8shO/h/syXGOy69DvqaskQhCaoqeiWFBG20VQpq8PtodneuaawNLAFa8HJSRSBdrc447fO1AO8eTZ7jL1" +
    "0Q+3D5oZzmvYrLNK5UnQM0zyUEYZp6f97n8mw4Ws3SBKOPjMovanNZVb0KG/AerP4Hto5uma+4FkZrY1mDSxHl8Sigu2EAdB/bIhuCtuNBb+EODT" +
    "zuV/r/7Gecr89r8shkz33wjRwadiHyib232CQ/Z1lH9kg==";

const public_key = "-----BEGIN PUBLIC KEY-----\n" +
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqjKM07NnbEN9j19hzfZB\n" +
    "svnv1ooCLnY26YP2wKKap3WQ4tgySVLmEhHOiTu4nBMo2CBdnSUp5js8OW9krGMB\n" +
    "SjmLacO6kZLva6se3Y6Oyo79vlFJ/ESpCBgQRHxqeKL7SR+HgPkwpwkLkJJ8Md22\n" +
    "c4xqGwb1v3AIIynVcADckKTi+TZH7GUnhNye493++oE0lm0rjLIT5lCnrT+rPLJI\n" +
    "a2/Tnh1Nv9iumd0K3XhPE8yOdIJTOkPVpuo3REHfsj1hSHqJZa/r260NuXaQewPz\n" +
    "uRjuAuN8UjYKMuKj9+XBCewiRfli/ULYmityPXDQILLYqar+veOxSaTZPT/1JGtX\n" +
    "XwIDAQAB\n" +
    "-----END PUBLIC KEY-----"

const rawPayload = {
    "appId": "e496f228-f957-4fb2-abb6-98653321cee4",
    "createdAt": "2023-06-02T14:22:22Z",
    "data": {
        "id": 1,
        "first_name": "TTL",
        "last_name": "TEST",
        "email": "dgiametti0@nih.gov",
        "gender": "Male",
        "ip_address": "55.119.237.50"
    },
    "eventId": "cedfa9aa-1775-46eb-8055-11e46235c78f",
    "eventType": "switch-loss-started",
    "tenantId": "61890020",
    "version": 1,
    "eventSource": "string"
}
const payload = JSON.stringify(rawPayload);

verifySignatureJS(x_payload_signature, public_key, payload)

