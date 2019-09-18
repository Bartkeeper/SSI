
const express = require('express');
const path = require('path');
const { Credentials } = require('uport-credentials');
const bodyParser = require('body-parser');
const ngrok = require('ngrok');
const { decodeJWT } = require('did-jwt');
const transports = require('uport-transports').transport;
const message = require('uport-transports').message.util;


let endpoint = '';
const app = express();
console.log('Server start...');
app.use(bodyParser.json({ type: '*/*' }));

const credentials = new Credentials({
    appName: 'Login Example',
    did: 'did:ethr:0x35a307f9f2dead33ceca7fc6a9d7595f0ec00c0e',
    privateKey: 'db4510c0fffcc4b52e82dc20327ee4c4469da2a42469259c1afd15c575ee0a18',
});

// Login for Create Verification Example
app.get('/', (req, res) => {
    credentials.createDisclosureRequest({
        requested: ['name', 'email'],
        notifications: true,
        callbackUrl: `${endpoint}/callback`,
    }).then((requestToken) => {
        console.log(decodeJWT(requestToken)); // log request token to console
        const uri = message.paramsToQueryString(message.messageToURI(requestToken), { callback_type: 'post' });
        const qr = transports.ui.getImageDataURI(uri);
        res.send(`<div><img src="${qr}"/></div>`);
    });
});

// Verification Example POST
app.post('/callback', (req, res) => {
    const jwt = req.body.access_token;
    credentials.authenticateDisclosureResponse(jwt).then((creds) => {
        // take this time to perform custom authorization steps... then,
        // set up a push transport with the provided
        // push token and public encryption key (boxPub)

        console.log(credentials);

        const push = transports.push.send(creds.pushToken, creds.boxPub);

        credentials.createVerification({
            sub: creds.did,
            exp: Math.floor(new Date().getTime() / 1000) + 356 * 24 * 60 * 60,
            claim: {
                'EBA Staking Certificate': {
                    'Issued at': `${new Date()}`,
                    status: 'valid',
                    auditingGrade: '95%',
                    subject: 'Staking Facilities',
                },
            },
        }).then((attestation) => {
            console.log(`Encoded JWT sent to user: ${attestation}`);
            console.log(`Decodeded JWT sent to user: ${JSON.stringify(decodeJWT(attestation))}`);
            return push(attestation); // *push* the notification to the user's uPort mobile app.
            // eslint-disable-next-line no-shadow
        }).then((res) => {
            console.log(res);
            console.log('Push notification sent and should be recieved any moment...');
            console.log('Accept the push notification in the uPort mobile application');
            ngrok.disconnect();
        });
    });
});

// run the app server and tunneling service
const server = app.listen(8088, () => {
    ngrok.connect(8088).then((ngrokUrl) => {
        endpoint = ngrokUrl;
        console.log(`Verification Service running, open at ${endpoint}`);
    });
});

app.use('/static', express.static(path.join(__dirname, './static')));

app.listen(3001, () => {
    console.log('Example app listening on port 3001!');
});
