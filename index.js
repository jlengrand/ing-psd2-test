/* This is all based on https://developer.ing.com/openbanking/get-started (Create and sign the signing request)*/

const request = require('request');
const fs = require('fs');
const path = require('path');
const uuidv1 = require('uuid/v1');
const sha256 = require('crypto-js/sha256');
const Base64 = require('crypto-js/enc-base64');
const jwa = require('jwa');

// require('request').debug = true

const certFile = path.resolve(__dirname, 'example_eidas_client_tls.cer');
const keyFile = path.resolve(__dirname, 'example_eidas_client_tls.key');

const publicKey = fs.readFileSync(keyFile);

const reqDate = (new Date()).toUTCString();
// const reqId = uuidv1();
const reqId = "uuidgen";
const clientId = '5ca1ab1e-c0ca-c01a-cafe-154deadbea75';

const bodyValue = 'grant_type=client_credentials';
// const bodyHash = `SHA-256=${Base64.stringify(sha256(bodyValue))}`;
const bodyHash = "SHA-256=2k+Z28JKG40TiStU9w8qgHcIfLEsaEdgXAMa+Yt6nH0=";
// SHA-256=2k+Z28JKG40TiStU9w8qgHcIfLEsaEdgXAMa+Yt6nH0=
console.log("//////////////");
console.log(bodyHash);
console.log("SHA-256=2k+Z28JKG40TiStU9w8qgHcIfLEsaEdgXAMa+Yt6nH0=");
console.log("//////////////");
console.log(reqDate);
console.log("//////////////");

const signingString = `(request-target): post /oauth2/token
date: ${reqDate}
digest: ${bodyHash}
x-ing-reqid: ${reqId}`;

const rsa = jwa('RS256');
const signature = rsa.sign(signingString, publicKey);

const options = {
    url: 'https://api.sandbox.ing.com/oauth2/token',
    cert: fs.readFileSync(certFile),
    key: fs.readFileSync(keyFile),
    headers: [
        {
            name:"tpp-signature-certificate",
            value: "-----BEGIN CERTIFICATE-----MIID9TCCAt2gAwIBAgIESZYC0jANBgkqhkiG9w0BAQsFADByMR8wHQYDVQQDDBZBcHBDZXJ0aWZpY2F0ZU1lYW5zQVBJMQwwCgYDVQQLDANJTkcxDDAKBgNVBAoMA0lORzESMBAGA1UEBwwJQW1zdGVyZGFtMRIwEAYDVQQIDAlBbXN0ZXJkYW0xCzAJBgNVBAYTAk5MMB4XDTE5MDMwNDEzNTkwN1oXDTIwMDMwNDE0NTkwN1owPjEdMBsGA1UECwwUc2FuZGJveF9laWRhc19xc2VhbGMxHTAbBgNVBGEMFFBTRE5MLVNCWC0xMjM0NTEyMzQ1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxWVOA7gAntPONQAfmLCEpQUcdi2oNRkQ7HioxD1cIxsy9QRFNFhbl8bSW++oSh/Gdo2tds9Oe7i/54cxp7svQitBDvOLLqC5/4+xtNXOYLFVjQF2EyJWlFBq9ZEqmD/5uk8UpJHt9lqJZfuxUeF0ZA/NAADR3nEL1mSSbEqRpxRvdJ+rn+9DaquRBthZSlPJkOTKyQ9tzbTgmsrrzD1GLA8UMt6GqpYZnFvuJapa9yDHxEe1laazwgTmmcD0su/K5D9hqSWlbxEDp0Bud5GeEYVhV6Zqf2J8vMbTVD9UZHI9Bb0W99u1+NUyPKqV+jwgbmA37ehDaB17i4ABbItxAwIDAQABo4HGMIHDMBUGA1UdHwQOMAwwCqAIoAaHBH8AAAEwIQYDVR0jBBowGKAWBBRwSLteAMD0JvjEdNF40sRO37RyWTCBhgYIKwYBBQUHAQMEejB4MAoGBgQAjkYBAQwAMBMGBgQAjkYBBjAJBgcEAI5GAQYCMFUGBgQAgZgnAjBLMDkwEQYHBACBmCcBAwwGUFNQX0FJMBEGBwQAgZgnAQEMBlBTUF9BUzARBgcEAIGYJwECDAZQU1BfUEkMBlgtV0lORwwGTkwtWFdHMA0GCSqGSIb3DQEBCwUAA4IBAQB3TXQgvS+vm0CuFoILkAwXc/FKL9MNHb1JYc/TZKbHwPDsYJT3KNCMDs/HWnBD/VSNPMteH8Pk5Eh+PIvQyOhY3LeqvmTwDZ6lMUYk5yRRXXh/zYbiilZAATrOBCo02ymm6TqcYfPHF3kh4FHIVLsSe4m/XuGoBO2ru5sMUCxncrWtw4UXZ38ncms2zHbkH6TB5cSh2LXY2aZSX8NvYyHPCCw0jrkVm1/kAs69xM2JfIh8fJtycI9NvcoSd8HGSe/D5SjUwIFKTWXq2eCMsNEAG51qS0jWXQqPtqBRRTdu+AEAJ3DeIY6Qqg2mjk+i6rTMqSwFVqo7Cq7zHty4E7qK-----END CERTIFICATE-----"
        },
        {
            name: "Accept", 
            value: "application/json"
        },
        {
          name: 'Content-Type',
          value: 'application/x-www-form-urlencoded'
        },
        {
            name: 'Date',
            value: reqDate,
        },
        {
            name: 'X-ING-ReqID',
            value: reqId
        },
        {
            name: 'Digest',
            value: `${bodyHash}`
        },
        {
            name: 'authorization',
            value: `Signature keyId="${clientId}",algorithm="rsa-sha256",headers="(request-target) date digest x-ing-reqid",signature="${signature}"`
        }
      ],
    body : bodyValue
};

request.post(options,  (error, response, body) => {
  console.log('error:', error); // Print the error if one occurred
  console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received
//   console.log(response);
//   console.log(response.message);
  console.log('body:', body); // Print the HTML for the Google homepage.
});
