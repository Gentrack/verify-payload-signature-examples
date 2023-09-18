#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

int verify_signature(const char *x_payload_signature, const char *public_key, const char *payload) {
    char *timestamp = strtok(strdup(x_payload_signature), ",");
    timestamp = strtok(timestamp, "=");
    timestamp = strtok(NULL, "=");
    char *sigToVerify = strtok(NULL, ",");
    sigToVerify = strtok(sigToVerify, "=");
    sigToVerify = strtok(NULL, "=");

    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(public_key, -1);
    pkey = PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL);
    BIO_free(bio);

    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_new();
    EVP_VerifyInit(mdctx, EVP_sha512());
    char v[strlen(timestamp) + strlen(payload) + 2];
    sprintf(v, "%s.%s", timestamp, payload);
    EVP_VerifyUpdate(mdctx, v, strlen(v));
    int result = EVP_VerifyFinal(mdctx, (unsigned char *)sigToVerify, strlen(sigToVerify), pkey);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return result;
}


const char *x_payload_signature = "t=1693370036,v=Wu5ueKR+Zd1SJROgOY2+Uz\
aLL/MfmpbygRQbIlZfRahUlCrDnSEO1lEr63OzsbUg2M+XAFXsQsHR0T78CLcZR4rGXLefdI\
FOkdNuLBJa8shO/h/syXGOy69DvqaskQhCaoqeiWFBG20VQpq8PtodneuaawNLAFa8HJSRSB\
drc447fO1AO8eTZ7jL10Q+3D5oZzmvYrLNK5UnQM0zyUEYZp6f97n8mw4Ws3SBKOPjMovanN\
ZVb0KG/AerP4Hto5uma+4FkZrY1mDSxHl8Sigu2EAdB/bIhuCtuNBb+EODTzuV/r/7Gecr89\
r8shkz33wjRwadiHyib232CQ/Z1lH9kg==";

const char *public_key = "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqjKM07NnbEN9j19hzfZB\n"
    "svnv1ooCLnY26YP2wKKap3WQ4tgySVLmEhHOiTu4nBMo2CBdnSUp5js8OW9krGMB\n"
    "SjmLacO6kZLva6se3Y6Oyo79vlFJ/ESpCBgQRHxqeKL7SR+HgPkwpwkLkJJ8Md22\n"
    "c4xqGwb1v3AIIynVcADckKTi+TZH7GUnhNye493++oE0lm0rjLIT5lCnrT+rPLJI\n"
    "a2/Tnh1Nv9iumd0K3XhPE8yOdIJTOkPVpuo3REHfsj1hSHqJZa/r260NuXaQewPz\n"
    "uRjuAuN8UjYKMuKj9+XBCewiRfli/ULYmityPXDQILLYqar+veOxSaTZPT/1JGtX\n"
    "XwIDAQAB\n"
    "-----END PUBLIC KEY-----";
	
const char *payload = payload = "{\"appId\":\"e496f228-f957-4fb2-abb6-98653321cee4\""
",\"createdAt\":\"2023-06-02T14:22:22Z\",\"data\":{\"id\":1,\"first_name\":\"TTL\",\""
"last_name\":\"TEST\",\"email\":\"dgiametti0@nih.gov\",\"gender\":\"Male\",\"ip_address\""
":\"55.119.237.50\"},\"eventId\":\"cedfa9aa-1775-46eb-8055-11e46235c78f\",\"eventType\":\""
"switch-loss-started\",\"tenantId\":\"61890020\",\"version\":1,\"eventSource\":\"string\"}";

int result = verify_signature(x_payload_signature, public_key, payload);
printf("%d\n", result);
