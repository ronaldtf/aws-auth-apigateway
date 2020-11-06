var accessToken = undefined
var idToken = undefined
var jwtToken = undefined

var showSignInFields = function() {
    var auth = document.getElementById("auth")
    console.log(auth.style.display)
    if (idToken == undefined || idToken.jwtToken == undefined) {
        auth.style.display = "block"
    } else {
        auth.style.display = "none"
    }
}


var signIn = function() {
    doClear()
    output("Working...", document.getElementById("result"))
    var user = document.getElementById("username").value
    var pass = document.getElementById("password").value
    doSignIn(user, pass, function(err) {
        console.log("OK")
        doClear()
        if (err)
            output(err, document.getElementById("result"))
        else {
            output("User is signed in", document.getElementById("result"))
        }
        showSignInFields()
    })
}

var doSignIn = function(username, password, callback) {
    var userPoolData = { UserPoolId: config.UserPool, ClientId: config.UserPoolAppClient }
    var userPool = new AWSCognito.CognitoIdentityServiceProvider.CognitoUserPool(userPoolData)

    var authenticationData = { Username: username, Password: password };
    var authenticationDetails = new AWSCognito.CognitoIdentityServiceProvider.AuthenticationDetails(authenticationData)

    var userData = { Username: username, Pool: userPool }
    var user = new AWSCognito.CognitoIdentityServiceProvider.CognitoUser(userData)

    user.authenticateUser(authenticationDetails, {
        onSuccess: function(result) {
            accessToken = result.getAccessToken()
            idToken = result.getIdToken()
            callback(null)
        },
        onFailure: function(err) {
            console.log("Error from cognito promise: ", err);
            callback(err)
        },
        newPasswordRequired: function(userAttributes) {
            user.completeNewPasswordChallenge(password, null, this)
            callback(null)
        }
    });
}

var signOut = function() {
    accessToken = undefined
    idToken = undefined
    doClear()
    showSignInFields()
}

// Clear the results section
var doClear = function() {

    var tag = document.getElementById("result")
    if (tag != null && tag.hasChildNodes())
        tag.removeChild(tag.children[0]);
    var tag2 = document.getElementById("result2")
    if (tag != null && tag2.hasChildNodes())
        tag2.removeChild(tag2.children[0]);
}

// Show results section
var output = function(inp, tag) {
    tag.appendChild(document.createElement('pre')).innerHTML = inp;
}

// Decode a token to see its contents in a readable format
var decodeToken = function(token) {
    var header = JSON.parse(atob(token.split('.')[0]));
    var payload = JSON.parse(atob(token.split('.')[1]));
    var tokenDecoded = {
        "header": header,
        "payload": payload
    }
    return tokenDecoded
}

// Parse a JWT token
function parseJwt(token) {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(window.atob(base64));
}

// Display token content in the results section
var showToken = function() {
    if (idToken !== undefined && idToken.jwtToken !== undefined) {
        var idTokenDecoded = decodeToken(idToken.jwtToken)

        doClear()
        output(JSON.stringify(idTokenDecoded, null, 2), document.getElementById("result"))
        output(idToken.jwtToken, document.getElementById("result2"))
    } else {
        doClear()
        output("No token", document.getElementById("result2"))
    }
}

// Display an S3 key file given the input credentials
var accessS3 = function(awsAccessKeyId, awsSecretAccessKey, awsSessionToken) {

    if (awsAccessKeyId !== undefined && awsSecretAccessKey !== undefined && awsSessionToken !== undefined) {

        var s3 = new AWS.S3({
            region: config.Region,
            accessKeyId: awsAccessKeyId,
            secretAccessKey: awsSecretAccessKey,
            sessionToken: awsSessionToken
        });

        var paramsS3 = {
            Bucket: config.ReferredBucket,
            Key: config.S3key
        }
        s3.getObject(paramsS3, function(err, data) {
            if (err) {
                console.log(err)
                output(String.fromCharCode.apply(null, "OPERATION NOT ALLOWED: " + err), document.getElementById("result"))
            } else {
                doClear()
                console.log(data)
                output(String.fromCharCode.apply(null, data.Body), document.getElementById("result"))
            }
        })
    } else {
        doClear()
        output("No token", document.getElementById("result"))
    }
}

// Perform a signed API Gateway request with the input credentials and display the result in the result section
var callApiGatewaySignedIAM = function(awsAccessKeyId, awsSecretAccessKey, awsSessionToken, resource) {

    var credentials = {
        accessKeyId: awsAccessKeyId,
        secretAccessKey: awsSecretAccessKey,
        sessionToken: awsSessionToken
    };

    apigateway.makeRequest(credentials, resource, 'GET', undefined, undefined, function(returnedData) {
        doClear()
        if (returnedData['status'] == 200) {
            output(returnedData['data']['body'], document.getElementById("result"))
        } else {
            output("OPERATION NOT ALLOWED: " + returnedData['status'], document.getElementById("result"))
        }
    })

}

// Perform a request to API Gateway (not signed)
var callApiGateway = function(resource, accessToken = null) {
    if (accessToken == null)
        accessToken = ''

    $.ajax({
        url: config.ApiEndpoint + resource,
        type: 'GET',
        crossDomain: true,
        contentType: 'application/json',
        dataType: 'json',
        data: JSON.stringify(''),
        headers: {
            authorization: accessToken
        },
        success: function(data) {
            doClear()
            output(data['body'], document.getElementById("result"));
        },
        error: function(err) {
            doClear()
            output("OPERATION NOT ALLOWED: " + JSON.stringify(err), document.getElementById("result"))
        }
    });
}

// Perform an action give the Cognito User Pool custom domain
var performActionCustomDomainCognito = function(action, resource, token) {

    if (action == 's3' || action == 'apigatewayIAM') {
        const loginId = 'cognito-idp.' + config.Region + '.amazonaws.com/' + config.UserPool
        AWS.config.region = config.Region
        AWS.config.credentials = new AWS.CognitoIdentityCredentials({
            IdentityPoolId: config.FederatedIdentity,
            Logins: {
                [loginId]: token
            }
        });

        AWS.config.credentials.get(function(error) {
            if (error) {
                alert(error)
            } else {
                var accessKey = AWS.config.credentials.accessKeyId
                var secretKey = AWS.config.credentials.secretAccessKey
                var sessionToken = AWS.config.credentials.sessionToken
                if (action == 's3')
                    accessS3(accessKey, secretKey, sessionToken)
                else // action == apigatewayIAM
                    callApiGatewaySignedIAM(accessKey, secretKey, sessionToken, resource)
            }
        })
    } else
    if (action == 'apigateway') {
        callApiGateway(resource)
    } else if (action == 'apigatewayCognito') {
        callApiGateway(resource, token)
    } else {
        doClear()
        if (idToken !== undefined && idToken.jwtToken !== undefined)
            output(JSON.stringify(parseJwt(idToken.jwtToken), undefined, 4), document.getElementById("result"))
        else {
            doClear()
            output("No token", document.getElementById("result"))
        }
    }
}

// Perform an action given the input parameters
var performAction = function(action, resource, accessKeyId, secretAccessKey, sessionToken) {
    if (action == 's3') {
        console.log(accessKeyId)
        console.log(secretAccessKey)
        console.log(sessionToken)
        accessS3(accessKeyId, secretAccessKey, sessionToken)
    } else if (action == 'apigatewayIAM') {
        callApiGatewaySignedIAM(accessKeyId, secretAccessKey, sessionToken, resource)
    } else if (action == 'apigateway') {
        callApiGateway(resource)
    } else if (action == 'apigatewayCognito') {
        callApiGateway(resource, null)
    } else {
        var credentials = {
            "accessKeyId": accessKeyId,
            "secretAccessKey": secretAccessKey,
            "sessionToken": sessionToken
        }
        doClear()
        output(JSON.stringify(credentials, null, 2), document.getElementById("result"))
    }
}

// Get credentials through an assume role and perform a given action
var doButtonActionSTS = function(action, resource) {

    // Set credentials
    AWS.config.credentials = new AWS.WebIdentityCredentials({
        RoleArn: config.RoleIAMAuthViaSTS,
        WebIdentityToken: idToken
    });

    // Do assume role
    var paramsSTS = {
        DurationSeconds: 3600,
        RoleArn: config.RoleIAMAuthViaSTS,
        RoleSessionName: "test",
        WebIdentityToken: idToken
    };
    var sts = new AWS.STS();
    sts.assumeRoleWithWebIdentity(paramsSTS, function(err, data) {
        // Perform an action if possible
        if (err) {
            output(String.fromCharCode.apply(null, "OPERATION NOT ALLOWED: " + err), document.getElementById("result"))
        } else {
            performAction(action, resource, data.Credentials.AccessKeyId, data.Credentials.SecretAccessKey, data.Credentials.SessionToken)

        }
    });

}

// Perform an action given the Cognito User Pool credentials (from Custom Domain)
var doButtonActionCognito = function(action = null, resource = null) {
    doClear()
    output("Working...", document.getElementById("result"))
    if ((idToken == undefined || idToken.jwtToken == undefined) && action !== "apigateway") {
        doClear()
        output("No token", document.getElementById("result"))
    } else {
        var token = ""
        if (action != "apigateway")
            token = idToken.jwtToken
        performActionCustomDomainCognito(action, resource, token)
    }
}