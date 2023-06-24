// Install dependencies: npm i usb ws
// Run: node epicbox_send.js

// Use strict
"use strict";


// Requires
const WebSocket = require("ws");
const BigNumber = require("../../../tests/mimblewimble_coin/functional_tests/bignumber.js-9.1.1.js");
const Common = require("../../../tests/mimblewimble_coin/functional_tests/common.js");
const Mqs = require("../../../tests/mimblewimble_coin/functional_tests/mqs.js");
const UsbTransport = require("../../../tests/mimblewimble_coin/functional_tests/main.js");
const HardwareWalletDefinitions = require("../../../tests/mimblewimble_coin/functional_tests/hardware_wallet_definitions.js");


// Constants

// Destination
const DESTINATION = "esZ1P3crbc2XCHaGf7fQCGEcbnpgTBngPcZwciZZBbbdmPryFNEA@epicbox.epic.tech";

// Data
const DATA = "Hello, World!";

// Epicbox server
const EPICBOX_SERVER = "wss://epicbox.epic.tech:443";

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
	connection.on("open", async function() {
	
		// Display message
		console.log("Connected to server");
		
		// Display message
		console.log("Getting encrypted data and signature from hardware wallet");
		
		// Start encrypting data on the hardware wallet
		let response = await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_START_ENCRYPTING_SLATE_MESSAGE_TYPE, {
				
			// Coin type
			"Coin Type": EPIC_WALLET_TYPE,
			
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
				"public_key": DESTINATION.split("@")[0],
				"domain": DESTINATION.split("@")[1],
				"port": null
			},
			"nonce": Common.toHexString(nonce),
			"salt": Common.toHexString(salt),
			"encrypted_message": Common.toHexString(encryptedData)	
		});
		
		// Display message
		console.log("Sending message to server");
		
		// Send message to the server
		connection.send(JSON.stringify({
			"type": "PostSlate",
			"from": epicboxAddress,
			"to": DESTINATION.split("@")[0],
			"str": message,
			"signature": Common.toHexString(signature)
		}));
		
		// Close connection
		connection.close();
	});
})();
