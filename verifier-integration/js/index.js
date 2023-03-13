const express = require('express');
const {auth, resolver, loaders} = require('@iden3/js-iden3-auth')
const getRawBody = require('raw-body')

const app = express();
const port = 8080;

app.use(express.static('static'));

app.get("/api/sign-in", (req, res) => {
    console.log('get Auth Request');
    GetAuthRequest(req,res);
});

app.post("/api/callback", (req, res) => {
    console.log('callback');
    Callback(req,res);
});

app.listen(port, () => {
    console.log('server running on port 8080');
});

// Create a map to store the auth requests and their session IDs
const requestMap = new Map();

		// GetQR returns auth request
		async function GetAuthRequest(req,res) {

			const sessionId = 1;
			const request = require('./requests/qrValueProofRequestExample.json');
			 
			// Store auth request in map associated with session ID
			requestMap.set(`${sessionId}`, request);

			return res.status(200).json(request);
        }

        // Callback verifies the proof after sign-in callbacks
		async function Callback(req,res) {

			// Get session ID from request
			const sessionId = req.query.sessionId;

			// get JWZ token params from the post request
			const raw = await getRawBody(req);
			const tokenStr = raw.toString().trim();

			const ethURL = '<MUMBAI_RPC_URL>';
			const contractAddress = "0x134B1BE34911E39A8397ec6289782989729807a4"
			const keyDIR = "../keys"

			const ethStateResolver = new resolver.EthStateResolver(
				ethURL,
				contractAddress,
			  );

			const resolvers = {
				['polygon:mumbai']: ethStateResolver,
			};
							 

			// fetch authRequest from sessionID
			const authRequest = requestMap.get(`${sessionId}`);
				
			// Locate the directory that contains circuit's verification keys
			const verificationKeyloader = new loaders.FSKeyLoader(keyDIR);
			const sLoader = new loaders.UniversalSchemaLoader('ipfs.io');

			// EXECUTE VERIFICATION
			const verifier = new auth.Verifier(
			verificationKeyloader,
			sLoader,
			resolvers,
			);


		try {
			const opts = {
				AcceptedStateTransitionDelay: 5 * 60 * 1000, // 5 minute
			  };		
			authResponse = await verifier.fullVerify(tokenStr, authRequest, opts);
		} catch (error) {
		return res.status(500).send(error);
		}
		return res.status(200).json({
			from: authResponse.from,
			message: "user with ID: " + authResponse.from + " succesfully authenticated"
		});
	}
