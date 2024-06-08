// Install dependencies: npm i usb ws
// Run: node epicbox_listener.js

// Use strict
"use strict";


// Requires
const WebSocket = require("ws");
const BigNumber = require("../../../tests/mimblewimble_coin/functional_tests/bignumber.js-9.1.1.js");
const Common = require("../../../tests/mimblewimble_coin/functional_tests/common.js");
const UsbTransport = require("../../../tests/mimblewimble_coin/functional_tests/main.js");
const HardwareWalletDefinitions = require("../../../tests/mimblewimble_coin/functional_tests/hardware_wallet_definitions.js");


// Constants

// Epicbox server
const EPICBOX_SERVER = "wss://epicbox.epiccash.com:443";

// EPIC wallet type
const EPIC_WALLET_TYPE = 2;

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
	console.log("Getting Epicbox address from hardware wallet");
	
	// Get the Epicbox address from the hardware wallet
	const epicboxAddress = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_GET_ADDRESS_MESSAGE_TYPE, {
	
		// Coin type
		"Coin Type": EPIC_WALLET_TYPE,
		
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
	console.log("Epicbox address is " + epicboxAddress);
	
	// Display message
	console.log("Connecting to server");
	
	// Connect to the server
	const connection = new WebSocket(EPICBOX_SERVER);
	
	// Connection on message
	connection.on("message", async function(data) {
	
		// Parse data
		const message = JSON.parse(data);
		
		// Check message's type
		switch(message["type"]) {
		
			// Challenge
			case "Challenge":
			
				// Display message
				console.log("Connected to server");
				
				// Display message
				console.log("Getting default challenge signature from hardware wallet");
			
				// Get the default challenge signature from the hardware wallet
				const signature = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_GET_MQS_CHALLENGE_SIGNATURE_MESSAGE_TYPE, {
							
					// Coin type
					"Coin Type": EPIC_WALLET_TYPE,
					
					// Network type
					"Network Type": MAINNET_NETWORK_TYPE,
					
					// Account
					"Account": ACCOUNT,
					
					// Index
					"Index": INDEX
				
				}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_MQS_CHALLENGE_SIGNATURE_MESSAGE_TYPE))["MQS Challenge Signature"].at(-1);
				
				// Display message
				console.log("Default challenge signature is " + Common.toHexString(signature));
				
				// Display message
				console.log("Waiting for messages server");
				
				// Send subscription request to the server
				connection.send(JSON.stringify({
					"type": "Subscribe",
					"address": epicboxAddress,
					"signature": Common.toHexString(signature)
				}));
				
				// Break
				break;
			
			// Slate
			case "Slate":
			
				// // Display message
				console.log("Message received");
				
				// Display message
				console.log(message);
				
				// Close connection
				connection.close();
			
				// Break
				break;
		}
	});
})();
