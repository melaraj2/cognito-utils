let axios = require('axios');
let cognitoPublicKeys = [];
let jwt = require('jsonwebtoken');
let jwkToPem = require('jwk-to-pem');



let cognitoUtils={};

let cogAuth;


function getCognitoPublicKeys(decodedToken) {
    return new Promise((resolve, reject) => {



        if (cognitoPublicKeys.length > 0) {
            resolve(cognitoPublicKeys);
        } else {
            axios.get(decodedToken.payload.iss + '/.well-known/jwks.json', {headers: {'content-type': 'application/json'}}).then((response) => {
                console.log("here");
                for (const key of response.data.keys) {
                    cognitoPublicKeys[key.kid] = key;
                }

                resolve(cognitoPublicKeys);
            }).catch((err) => {
                reject(err);
            });
        }

    });
}

function authenticateToken(tokenkey,token) {

    return new Promise((resolve, reject) => {
        var decoded = jwt.decode(token, {complete: true});

        getCognitoPublicKeys(decoded).then(pubKeys => {
            var jwk = pubKeys[decoded.header.kid]
            var pem = jwkToPem(jwk);
            jwt.verify(token, pem, {algorithms: [decoded.header.alg]}, function (err, decodedToken) {
                if (err) {
                    reject(err);
                } else {
                    var resp={};
                    resp.tokenKey=tokenkey;
                    resp.token=decoded;

                    resolve(resp);
                }
            });
        }).catch(err => {
            reject(err);
        });


    });
}

cognitoUtils.getCognitoTokens=function getCognitoTokens(code){

    return new Promise((resolve,reject)=>{
        if(cogAuth==null){
            buff = new Buffer(cognitoUtils.clientid + ":" + cognitoUtils.client_secret);
            cogAuth = buff.toString('base64');
        }

        var result={};
        axios.post('https://auth.myrx.cloud/oauth2/token', "grant_type=authorization_code&redirect_uri=http://localhost:3000&code=" + code, {
            headers: {
                Authorization: "Basic " + cogAuth + ":",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        })
            .then((response) => {
                console.log(`statusCode: ${response.status}`);
                console.log(response.data.id_token);

                promises=[];
                promises.push(authenticateToken("id_token",response.data["id_token"]));
                promises.push(authenticateToken("access_token",response.data["access_token"]));

                Promise.all(promises).then(tokens=>{
                    result={};
                    result.tokens={};
                    result.refreshToken=response.data.refresh_token;
                    result.expires_in=response.data.expires_in;
                    for (var token  of tokens) {
                        result.tokens[token.tokenKey]=token.token;
                    }

                    resolve(result);

                }).catch(error=>{
                    reject(error);
                });
            })
            .catch((error) => {
                console.error(error)
                reject(err);
            });
    });
};

module.exports=cognitoUtils;

