// Install dependencies: npm i usb
// Run: node mqs_listener.js

// Use strict
"use strict";


// Requires
const https = require("https");
const BigNumber = require("../../../tests/mimblewimble_coin/functional_tests/bignumber.js-9.1.1.js");
const Common = require("../../../tests/mimblewimble_coin/functional_tests/common.js");
const UsbTransport = require("../../../tests/mimblewimble_coin/functional_tests/main.js");
const HardwareWalletDefinitions = require("../../../tests/mimblewimble_coin/functional_tests/hardware_wallet_definitions.js");


// Constants

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
	
	// Initialize hardware wallet
	await hardwareWallet.send(HardwareWalletDefinitions.TREZOR_INITIALIZE_MESSAGE_TYPE, {}, HardwareWalletDefinitions.TREZOR_FEATURES_MESSAGE_TYPE);
	
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
	console.log("Getting timestamp from server");
	
	// Get timestamp from the server
	const timestamp = await sendGetRequest(MQS_SERVER  + "/timenow?address=" + mqsAddress);
	
	// Display message
	console.log("Timestamp is " + timestamp);
	
	// Get time zone offset
	const timeZoneOffset = (new Date()).getTimezoneOffset();
	
	// Display message
	console.log("Getting challenge signature from hardware wallet");
	
	// Get the challenge signature from the hardware wallet
	const signature = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_GET_MQS_CHALLENGE_SIGNATURE_MESSAGE_TYPE, {
				
		// Coin type
		"Coin Type": MWC_WALLET_TYPE,
		
		// Network type
		"Network Type": MAINNET_NETWORK_TYPE,
		
		// Account
		"Account": ACCOUNT,
		
		// Index
		"Index": INDEX,
		
		// Timestamp
		"Timestamp": new BigNumber(timestamp),
		
		// Time zone offset
		"Time Zone Offset": new BigNumber(timeZoneOffset)
	
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_MQS_CHALLENGE_SIGNATURE_MESSAGE_TYPE))["MQS Challenge Signature"].at(-1);
	
	// Display message
	console.log("Challenge signature is " + Common.toHexString(signature));
	
	// Display message
	console.log("Waiting for messages from server");
	
	// Get messages from the server
	const messages = await sendGetRequest(MQS_SERVER  + "/listener?address=" + mqsAddress + "&signature=" + Common.toHexString(signature) + "&time_now=" + timestamp + "&delTo=nil&first=true");
	
	// Display message
	console.log("Message received");
	
	// Display message
	console.log(messages);
})();


// Supporting function implementation

// Send GET request
function sendGetRequest(url) {

	// Return promise
	return new Promise(function(resolve, reject) {
	
		// Initialize data
		let data = "";
	
		// Create request
		const request = https.request(url, function(response) {
		
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
		
		// Send request
		request.end();
	});
}
