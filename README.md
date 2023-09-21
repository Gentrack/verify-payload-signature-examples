# Payload Signature Verification
​
When Gentrack sends events, one of the headers contains a x-payload-signature which allows the recipient to verify the authenticity of the event. It contains a timestamp, and a signature. The signature is calculated based on the message contents, and the timestamp provided, using a private key that was generated when your application was created. 
​
The following repository has code in multiple languages which shows how to verify the signature. 