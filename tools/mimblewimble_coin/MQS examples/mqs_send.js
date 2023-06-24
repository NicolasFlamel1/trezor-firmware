// Install dependencies: npm i usb
// Run: node mqs_send.js

// Use strict
"use strict";


// Requires
const https = require("https");
const BigNumber = require("../../../tests/mimblewimble_coin/functional_tests/bignumber.js-9.1.1.js");
const Common = require("../../../tests/mimblewimble_coin/functional_tests/common.js");
const Mqs = require("../../../tests/mimblewimble_coin/functional_tests/mqs.js");
const UsbTransport = require("../../../tests/mimblewimble_coin/functional_tests/main.js");
const HardwareWalletDefinitions = require("../../../tests/mimblewimble_coin/functional_tests/hardware_wallet_definitions.js");


// Constants

// Destination
const DESTINATION = "q5adDmdw32Rsx6GP79NUGgGefSuHEUWbAZCXWFZpdo7TW6hERNRU";

// Data
const DATA = "Hello, World!";

// MQS server
const MQS_SERVER = "https://mqs.mwc.mw:443";

// MWC wallet type
const MWC_WALLET_TYPE = 0;

// Mainnet network type
const MAINNET_NETWORK_TYPE = 0;

// MQS address type
const MQS_ADDRESS_TYPE = 0;

// Account
const ACCOUNT = new BigNumber(0);

// Index
const INDEX = new BigNumber(0);

// USB vendor ID
const USB_VENDOR_ID = 0x1209;

// USB product ID
const USB_PRODUCT_ID = 0x53C1;


// Main fucntion
(async function() {

	// Display message
	console.log("Connecting to hardware wallet");

	// Connect to the hardware wallet using USB
	const hardwareWallet = await UsbTransport.getDevice(USB_VENDOR_ID, USB_PRODUCT_ID);
	
	// Display message
	console.log("Getting MQS address from hardware wallet");
	
	// Get the MQS address from the hardware wallet
	const mqsAddress = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_GET_ADDRESS_MESSAGE_TYPE, {
	
		// Coin type
		"Coin Type": MWC_WALLET_TYPE,
		
		// Network type
		"Network Type": MAINNET_NETWORK_TYPE,
		
		// Address type
		"Parameter One": MQS_ADDRESS_TYPE,
		
		// Account
		"Account": ACCOUNT,
		
		// Index
		"Index": INDEX
		
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_ADDRESS_MESSAGE_TYPE))["Address"].at(-1);
	
	// Display message
	console.log("MQS address is " + mqsAddress);
	
	// Display message
	console.log("Getting encrypted data and signature from hardware wallet");
	
	// Start encrypting data on the hardware wallet
	let response = await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_START_ENCRYPTING_SLATE_MESSAGE_TYPE, {
				
		// Coin type
		"Coin Type": MWC_WALLET_TYPE,
		
		// Network type
		"Network Type": MAINNET_NETWORK_TYPE,
		
		// Account
		"Account": ACCOUNT,
		
		// Index
		"Index": INDEX,
		
		// Recipient address
		"Recipient Address": (new TextEncoder()).encode(DESTINATION)
	
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_ENCRYPTED_SLATE_NONCE_AND_SALT_MESSAGE_TYPE);
	
	// Get nonce from response
	const nonce = response["Nonce"].at(-1);
	
	// Get salt from response
	const salt = response["Salt"].at(-1);
	
	// Continue encrypting data on the hardware wallet
	let encryptedData = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_CONTINUE_ENCRYPTING_SLATE_MESSAGE_TYPE, {
			
		// Data
		"Data": (new TextEncoder()).encode(DATA)
	
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_ENCRYPTED_SLATE_DATA_MESSAGE_TYPE))["Encrypted Data"].at(-1);
	
	// Finish encrypting data on the hardware wallet
	response = await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_FINISH_ENCRYPTING_SLATE_MESSAGE_TYPE, {}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_ENCRYPTED_SLATE_TAG_AND_SIGNATURE_MESSAGE_TYPE);
	
	// Get tag from response
	const tag = response["Tag"].at(-1);
	
	// Get signature from response
	const signature = response["MQS Message Signature"].at(-1);
	
	// Append tag to encrypted data
	encryptedData = Common.mergeArrays([encryptedData, tag]);
	
	// Display message
	console.log("Encrypted data is " + Common.toHexString(encryptedData));
	
	// Display message
	console.log("Signature is " + Common.toHexString(signature));
	
	// Create message
	const message = JSON.stringify({
		"destination": {
			"public_key": DESTINATION,
			"domain": "",
			"port": null
		},
		"nonce": Common.toHexString(nonce),
		"salt": Common.toHexString(salt),
		"encrypted_message": Common.toHexString(encryptedData)	
	});
	
	// Display message
	console.log("Sending message to server");
	
	// Send message to the server
	const serverResponse = await sendPostRequest(MQS_SERVER  + "/sender?address=" + DESTINATION, "mapmessage=" + encodeURIComponent(message) + "&from=" + mqsAddress + "&signature=" + Common.toHexString(signature));
	
	// Display message
	console.log("Server response is " + serverResponse);
})();


// Supporting function implementation

// Send POST request
function sendPostRequest(url, payload) {

	// Return promise
	return new Promise(function(resolve, reject) {
	
		// Initialize data
		let data = "";
	
		// Create request
		const request = https.request(url, {
			"method": "POST",
			"headers": {
				"Content-Type": "application/x-www-form-urlencoded",
				"Content-Length": payload["length"],
			},
		}, function(response) {
		
			// Response data event
			response.on("data", function(chunk) {
			
				// Append chunk to data
				data += chunk.toString();
			});
		
			// Response end event
			response.on("end", function() {
			
				// Resolve data
				resolve(data);
			});
		
		// Request error event
		}).on("error", function(error) {
		
			// Reject
			reject();
		});
		
		// Add payload to request
		request.write(payload);
		
		// Send request
		request.end();
	});
}
