const crypto = require('crypto');
const util = require('util');
const base64us = require('urlsafe-base64')

const keyCurve = crypto.createECDH('prime256v1');
keyCurve.generateKeys();
const publicKey = keyCurve.getPublicKey();
const privateKey = keyCurve.getPrivateKey();
const auth = crypto.randomBytes(16)

console.log( "public key="+ base64us.encode(publicKey));
console.log( "private key="+ base64us.encode(privateKey));
console.log( "auth="+ base64us.encode(auth));

/*
function decodeBase64(src){
    return new Buffer(src,'base64').toString('UTF-8')
}

console.log("JWT Info="+decodeBase64('eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9'))
console.log("JWT Data="+decodeBase64('eyJhdWQiOiJodHRwczovL21hc3RvZG9uLW1zZy5qdWdnbGVyLmpwIiwiZXhwIjoxNTI2MTMzNTA4LCJzdWIiOiJtYWlsdG86In0'))
*/
