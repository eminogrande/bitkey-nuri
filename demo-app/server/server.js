const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json());

const users = new Map();
const authenticatorsByUserId = new Map();
const challengesByUserId = new Map();

const rpID = process.env.RP_ID || 'localhost';
const rpName = 'Bitkey FIDO2 Demo';
const origin = process.env.ORIGIN || 'http://localhost:8080';

function generateRandomId() {
  return crypto.randomBytes(16).toString('hex');
}

app.post('/api/register/start', (req, res) => {
  const { username } = req.body;
  
  if (!users.has(username)) {
    const userId = generateRandomId();
    users.set(username, { id: userId, username });
  }
  
  const user = users.get(username);
  
  const options = generateRegistrationOptions({
    rpName,
    rpID,
    userID: user.id,
    userName: username,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
      authenticatorAttachment: 'platform'
    }
  });
  
  challengesByUserId.set(user.id, options.challenge);
  
  res.json(options);
});

app.post('/api/register/complete', async (req, res) => {
  const { username, attestationResponse } = req.body;
  
  if (!users.has(username)) {
    return res.status(400).json({ error: 'User not found' });
  }
  
  const user = users.get(username);
  const expectedChallenge = challengesByUserId.get(user.id);
  
  if (!expectedChallenge) {
    return res.status(400).json({ error: 'Challenge not found' });
  }
  
  try {
    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID
    });
    
    const { verified, registrationInfo } = verification;
    
    if (verified && registrationInfo) {
      const { credentialID, credentialPublicKey, counter } = registrationInfo;
      
      const authenticator = {
        credentialID: Buffer.from(credentialID).toString('base64url'),
        credentialPublicKey,
        counter
      };
      
      if (!authenticatorsByUserId.has(user.id)) {
        authenticatorsByUserId.set(user.id, []);
      }
      
      authenticatorsByUserId.get(user.id).push(authenticator);
      
      challengesByUserId.delete(user.id);
      
      return res.json({ verified: true });
    }
    
    return res.status(400).json({ error: 'Verification failed' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: error.message });
  }
});

app.post('/api/authenticate/start', (req, res) => {
  const { username } = req.body;
  
  if (!users.has(username)) {
    return res.status(400).json({ error: 'User not found' });
  }
  
  const user = users.get(username);
  const userAuthenticators = authenticatorsByUserId.get(user.id) || [];
  
  if (userAuthenticators.length === 0) {
    return res.status(400).json({ error: 'No authenticators registered for this user' });
  }
  
  const options = generateAuthenticationOptions({
    rpID,
    allowCredentials: userAuthenticators.map(authenticator => ({
      id: Buffer.from(authenticator.credentialID, 'base64url'),
      type: 'public-key'
    })),
    userVerification: 'preferred'
  });
  
  challengesByUserId.set(user.id, options.challenge);
  
  res.json(options);
});

app.post('/api/authenticate/complete', async (req, res) => {
  const { username, assertionResponse } = req.body;
  
  if (!users.has(username)) {
    return res.status(400).json({ error: 'User not found' });
  }
  
  const user = users.get(username);
  const expectedChallenge = challengesByUserId.get(user.id);
  
  if (!expectedChallenge) {
    return res.status(400).json({ error: 'Challenge not found' });
  }
  
  const userAuthenticators = authenticatorsByUserId.get(user.id) || [];
  const credentialID = assertionResponse.id;
  
  const authenticator = userAuthenticators.find(
    authr => authr.credentialID === credentialID
  );
  
  if (!authenticator) {
    return res.status(400).json({ error: 'Authenticator not found' });
  }
  
  try {
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: Buffer.from(authenticator.credentialID, 'base64url'),
        credentialPublicKey: authenticator.credentialPublicKey,
        counter: authenticator.counter
      }
    });
    
    const { verified, authenticationInfo } = verification;
    
    if (verified) {
      authenticator.counter = authenticationInfo.newCounter;
      
      challengesByUserId.delete(user.id);
      
      return res.json({ 
        verified: true,
        user: {
          id: user.id,
          username: user.username
        }
      });
    }
    
    return res.status(400).json({ error: 'Verification failed' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: error.message });
  }
});

app.get('/api/users', (req, res) => {
  const userList = Array.from(users.values()).map(user => ({
    id: user.id,
    username: user.username,
    authenticators: (authenticatorsByUserId.get(user.id) || []).length
  }));
  
  res.json(userList);
});

app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'FIDO2 Demo Server is running' });
});

app.listen(port, '0.0.0.0', () => {
  console.log(`FIDO2 demo server running on port ${port}`);
});
