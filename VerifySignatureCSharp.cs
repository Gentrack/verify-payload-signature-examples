using System;
using System.Security.Cryptography;
using System.Text;

public static bool VerifySignature(string x_payload_signature, string public_key, string payload)
{
    var parts = x_payload_signature.Split(',');
    var timestamp = parts[0].Split('=')[1];
    var sigToVerify = parts[1].Split('=')[1];

    using (var rsa = RSA.Create())
    {
        rsa.ImportFromPem(public_key);
        var v = $"{timestamp}.{payload}";
        var data = Encoding.UTF8.GetBytes(v);
        var signature = Convert.FromBase64String(sigToVerify);
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
    }
}

var x_payload_signature = "t=1693370036,v=Wu5ueKR+Zd1SJROgOY2+Uz\
aLL/MfmpbygRQbIlZfRahUlCrDnSEO1lEr63OzsbUg2M+XAFXsQsHR0T78CLcZR4rGXLefdI\
FOkdNuLBJa8shO/h/syXGOy69DvqaskQhCaoqeiWFBG20VQpq8PtodneuaawNLAFa8HJSRSB\
drc447fO1AO8eTZ7jL10Q+3D5oZzmvYrLNK5UnQM0zyUEYZp6f97n8mw4Ws3SBKOPjMovanN\
ZVb0KG/AerP4Hto5uma+4FkZrY1mDSxHl8Sigu2EAdB/bIhuCtuNBb+EODTzuV/r/7Gecr89\
r8shkz33wjRwadiHyib232CQ/Z1lH9kg==";
var public_key = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqjKM07NnbEN9j19hzfZB
svnv1ooCLnY26YP2wKKap3WQ4tgySVLmEhHOiTu4nBMo2CBdnSUp5js8OW9krGMB
SjmLacO6kZLva6se3Y6Oyo79vlFJ/ESpCBgQRHxqeKL7SR+HgPkwpwkLkJJ8Md22
c4xqGwb1v3AIIynVcADckKTi+TZH7GUnhNye493++oE0lm0rjLIT5lCnrT+rPLJI
a2/Tnh1Nv9iumd0K3XhPE8yOdIJTOkPVpuo3REHfsj1hSHqJZa/r260NuXaQewPz
uRjuAuN8UjYKMuKj9+XBCewiRfli/ULYmityPXDQILLYqar+veOxSaTZPT/1JGtX
XwIDAQAB
-----END PUBLIC KEY-----";
var payload = "some_payload";

var result = VerifySignature(x_payload_signature, public_key, payload);
Console.WriteLine(result);

