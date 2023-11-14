// Install dependencies: npm i usb
// Run: node main.js mimblewimble_coin emulator

// Use strict
"use strict";


// Requires
const udp = require("dgram");
const readline = require("readline");
const crypto = require("crypto")["webcrypto"];
const Blake2b = require("./BLAKE2b-0.0.2.js");
const Ed25519 = require("./Ed25519-0.0.22.js");
const X25519 = require("./X25519-0.0.23.js");
const Secp256k1Zkp = require("./secp256k1-zkp-0.0.29.js");
const BigNumber = require("./bignumber.js-9.1.1.js");
const sha256 = require("./js-sha256-0.10.0.js");
const Common = require("./common.js");
const Identifier = require("./identifier.js");
const Crypto = require("./crypto.js");
const Seed = require("./seed.js");
const Tor = require("./tor.js");
const Mqs = require("./mqs.js");
const Slatepack = require("./slatepack.js");
const Consensus = require("./consensus.js");
const NewProofBuilder = require("./new_proof_builder.js");
const Slate = require("./slate.js");
const SlateKernel = require("./slate_kernel.js");
const Age = require("./age.js");
const ProtocolBuffers = require("./protocol_buffers.js");
const HardwareWalletDefinitions = require("./hardware_wallet_definitions.js");


// Constants

// Mnemonic
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

// Seed key
const SEED_KEY = "IamVoldemort";

// Account
const ACCOUNT = new BigNumber(0);

// Index
const INDEX = new BigNumber(0);

// No payment proof type
const NO_PAYMENT_PROOF_TYPE = 0;

// MQS payment proof type
const MQS_PAYMENT_PROOF_TYPE = NO_PAYMENT_PROOF_TYPE + 1;

// Tor payment proof type
const TOR_PAYMENT_PROOF_TYPE = MQS_PAYMENT_PROOF_TYPE + 1;

// Slatepack payment proof type
const SLATEPACK_PAYMENT_PROOF_TYPE = TOR_PAYMENT_PROOF_TYPE + 1;

// MQS address type
const MQS_ADDRESS_TYPE = 0;

// Tor address type
const TOR_ADDRESS_TYPE = MQS_ADDRESS_TYPE + 1;

// Slatepack address type
const SLATEPACK_ADDRESS_TYPE = TOR_ADDRESS_TYPE + 1;

// Sending transaction message type
const SENDING_TRANSACTION_MESSAGE_TYPE = 0;

// Receiving transaction message type
const RECEIVING_TRANSACTION_MESSAGE_TYPE = SENDING_TRANSACTION_MESSAGE_TYPE + 1;

// Creating coinbase message type
const CREATING_COINBASE_MESSAGE_TYPE = RECEIVING_TRANSACTION_MESSAGE_TYPE + 1;

// MimbleWimble Coin capable
const MIMBLEWIMBLE_COIN_CAPABLE = 0xC7;

// Packet size
const PACKET_SIZE = 64;

// Emulator address
const EMULATOR_ADDRESS = "localhost";

// Emulator port
const EMULATOR_PORT = 21324;

// USB vendor ID
const USB_VENDOR_ID = 0x1209;

// USB product ID
const USB_PRODUCT_ID = 0x53C1;

// Default currency
const DEFAULT_CURRENCY = "mimblewimble_coin";


// Classes

// Emulator transport
class EmulatorTransport {

	// Constructor
	constructor(address, port) {
	
		// Set address
		this.address = address;
		
		// Set port
		this.port = port;
	}
	
	// Send
	send(type, data, allowedResponseType) {
	
		// Set self
		const self = this;
	
		// Return promise
		return new Promise(function(resolve, reject) {
		
			// Encoded the data
			const encodedData = (type.toFixed() in HardwareWalletDefinitions.SCHEMA === true) ? ProtocolBuffers.encode(type, data, HardwareWalletDefinitions.SCHEMA) : new Uint8Array([]);
			
			// Create payload
			const payload = Buffer.alloc(Uint16Array["BYTES_PER_ELEMENT"] + Uint32Array["BYTES_PER_ELEMENT"] + encodedData["length"]);
			payload.writeUint16BE(type);
			payload.writeUint32BE(encodedData["length"], Uint16Array["BYTES_PER_ELEMENT"]);
			Buffer.from(encodedData).copy(payload, Uint16Array["BYTES_PER_ELEMENT"] + Uint32Array["BYTES_PER_ELEMENT"]);
			
			// Create packets
			const packets = createPackets(payload);
			
			// Initialize response
			let response = Buffer.alloc(0);
		
			// Initialize first packet
			let firstPacket = true;
			
			// Initialize response type
			let responseType;
			
			// Initialize length
			let length;
			
			// Create client
			const client = udp.createSocket("udp4", function(message) {
			
				// Check if first packet
				if(firstPacket === true) {
				
					// Check if message is invalid
					if(message["length"] < "?##"["length"] + Uint16Array["BYTES_PER_ELEMENT"] + Uint32Array["BYTES_PER_ELEMENT"] || message.toString("utf8", 0, "?##"["length"]) !== "?##") {
					
						// Close client
						client.close(function() {
						
							// Reject
							reject();
						});
					}
					
					// Otherwise
					else {
				
						// Clear first packet
						firstPacket = false;
					
						// Get response type
						responseType = message.readUint16BE("?##"["length"]);
						
						// Get length
						length = message.readUInt32BE("?##"["length"] + Uint16Array["BYTES_PER_ELEMENT"]);
						
						// Append message to response
						response = Buffer.concat([response, message.subarray("?##"["length"] + Uint16Array["BYTES_PER_ELEMENT"] + Uint32Array["BYTES_PER_ELEMENT"])]);
					}
				}
				
				// Otherwise
				else {
				
					// Check if message is invalid
					if(message["length"] < "?"["length"] || message.toString("utf8", 0, "?"["length"]) !== "?") {
					
						// Close client
						client.close(function() {
						
							// Reject
							reject();
						});
					}
					
					// Otherwise
					else {
				
						// Append message to response
						response = Buffer.concat([response, message.subarray("?"["length"])]);
					}
				}
				
				// Check if entire response was received
				if(response["length"] >= length) {
				
					// Check if response type isn't allowed and isn't requesting a button be pressed, a passphrase to be provided, or a pin matrix to be provided and response isn't a failure response to a pin matrix
					if(responseType !== allowedResponseType && responseType !== HardwareWalletDefinitions.TREZOR_BUTTON_REQUEST_MESSAGE_TYPE && responseType !== HardwareWalletDefinitions.TREZOR_PASSPHRASE_REQUEST_MESSAGE_TYPE && responseType !== HardwareWalletDefinitions.TREZOR_PIN_MATRIX_REQUEST_MESSAGE_TYPE && (type !== HardwareWalletDefinitions.TREZOR_PIN_MATRIX_ACKNOWLEDGE_MESSAGE_TYPE || responseType !== HardwareWalletDefinitions.TREZOR_FAILURE_MESSAGE_TYPE)) {
					
						// Close client
						client.close(function() {
						
							// Check if response type is a failure response
							if(responseType === HardwareWalletDefinitions.TREZOR_FAILURE_MESSAGE_TYPE) {
						
								// Get failure from response
								const failure = ProtocolBuffers.decode(responseType, response.subarray(0, length), HardwareWalletDefinitions.SCHEMA);
								
								// Check if action or pin was canceled
								if(failure["Failure Type"].at(-1) === HardwareWalletDefinitions.TREZOR_ACTION_CANCELED_FAILURE_TYPE || failure["Failure Type"].at(-1) === HardwareWalletDefinitions.TREZOR_PIN_CANCELED_FAILURE_TYPE) {
								
									// Show message
									console.log("User canceled action on device");
								}
							}
							
							// Reject
							reject();
						});
					}
					
					// Otherwise check if response is requesting a button be pressed
					else if(responseType === HardwareWalletDefinitions.TREZOR_BUTTON_REQUEST_MESSAGE_TYPE) {
					
						// Close client
						client.close(function() {
						
							// Get button request from response
							const buttonRequest = ProtocolBuffers.decode(responseType, response.subarray(0, length), HardwareWalletDefinitions.SCHEMA);
							
							// Check if passphrase entry is requested
							if(buttonRequest["Button Request Type"].at(-1) === HardwareWalletDefinitions.TREZOR_PASSPHRASE_ENTRY_BUTTON_REQUEST_TYPE) {
							
								// Show message
								console.log("Enter passphrase on device");
							}
							
							// Check if pin entry is requested
							else if(buttonRequest["Button Request Type"].at(-1) === HardwareWalletDefinitions.TREZOR_PIN_ENTRY_BUTTON_REQUEST_TYPE) {
							
								// Show message
								console.log("Enter pin on device");
							}
						
							// Send button acknowledge request to the device
							self.send(HardwareWalletDefinitions.TREZOR_BUTTON_ACKNOWLEDGE_MESSAGE_TYPE, {}, allowedResponseType).then(function(response) {
							
								// Resolve response
								resolve(response);
								
							// Catch errors
							}).catch(function(error) {
							
								// Reject error
								reject(error);
							});
						});
					}
					
					// Otherwise check if response is requesting a passphrase to be provided
					else if(responseType === HardwareWalletDefinitions.TREZOR_PASSPHRASE_REQUEST_MESSAGE_TYPE) {
					
						// Close client
						client.close(function() {
						
							// Send passphrase acknowledge request to the device
							self.send(HardwareWalletDefinitions.TREZOR_PASSPHRASE_ACKNOWLEDGE_MESSAGE_TYPE, {
				
								// Passphrase
								"Passphrase": ""
								
							}, allowedResponseType).then(function(response) {
							
								// Resolve response
								resolve(response);
								
							// Catch errors
							}).catch(function(error) {
							
								// Reject error
								reject(error);
							});
						});
					}
					
					// Otherwise check if response is requesting a pin matrix to be provided
					else if(responseType === HardwareWalletDefinitions.TREZOR_PIN_MATRIX_REQUEST_MESSAGE_TYPE) {
					
						// Close client
						client.close(function() {
						
							// Create readline interface
							const readlineInterface = readline.createInterface({

								// Input
								"input": process.stdin,

								// Output
								"output": process.stdout
							});
						
							// Get pin
							readlineInterface.question("Enter pin: ", function(pin) {
							
								// Close readline interface
								readlineInterface.close();
								
								// Send pin matrix acknowledge request to the device
								self.send(HardwareWalletDefinitions.TREZOR_PIN_MATRIX_ACKNOWLEDGE_MESSAGE_TYPE, {
					
									// Pin
									"Pin": pin
									
								}, allowedResponseType).then(function(response) {
								
									// Resolve response
									resolve(response);
									
								// Catch errors
								}).catch(function(error) {
								
									// Reject error
									reject(error);
								});
							});
						});
					}
					
					// Otherwise check if response is failure response to a pin matrix
					else if(type === HardwareWalletDefinitions.TREZOR_PIN_MATRIX_ACKNOWLEDGE_MESSAGE_TYPE && responseType === HardwareWalletDefinitions.TREZOR_FAILURE_MESSAGE_TYPE) {
					
						// Close client
						client.close(function() {
							
							// Get failure from response
							const failure = ProtocolBuffers.decode(responseType, response.subarray(0, length), HardwareWalletDefinitions.SCHEMA);
							
							// Check if pin is invalid
							if(failure["Failure Type"].at(-1) === HardwareWalletDefinitions.TREZOR_PIN_CANCELED_FAILURE_TYPE || failure["Failure Type"].at(-1) === HardwareWalletDefinitions.TREZOR_PIN_INVALID_FAILURE_TYPE) {
							
								// Show message
								console.log("Invalid pin");
							}
							
							// Reject
							reject();
						});
					}
					
					// Otherwise
					else {
				
						// Close client
						client.close(function() {
						
							// Try
							try {
							
								// Decode response
								var decodedResponse = ProtocolBuffers.decode(responseType, response.subarray(0, length), HardwareWalletDefinitions.SCHEMA);
							}
							
							// Catch errors
							catch(error) {
							
								// Reject error
								reject(error);
								
								// Return
								return;
							}
							
							// Resolve decoded response
							resolve(decodedResponse);
						});
					}
				}
			});
			
			// Send packet
			let sendPacket = new Promise(function(resolve, reject) {
			
				// Resolve
				resolve();
			});
			
			// Initialize sending packets
			const sendingPackets = [sendPacket];
			
			// Go through all packets
			for(let i = 0; i < packets["length"]; ++i) {
			
				// Get packet
				let packet = packets[i];
				
				// Send next pack after previous packet is send
				sendPacket = sendPacket.then(function() {
				
					// Return promise
					return new Promise(function(resolve, reject) {
			
						// Send packet
						client.send(packet, self.port, self.address, function(error) {
						
							// Check if an error occurred
							if(error !== null) {
							
								// Reject error
								reject(error);
							}
							
							// Otherwise
							else {
							
								// Resolve
								resolve();
							}
						});
					});
						
				// Catch errors
				}).catch(function(error) {
				
					// Return promise
					return new Promise(function(resolve, reject) {
					
						// Reject error
						reject(error);
					});
				});
				
				// Append sending packet to list
				sendingPackets.push(sendPacket);
			}
			
			// Send all packets and catch errors
			Promise.all(sendingPackets).catch(function(error) {
			
				// Close client
				client.close(function() {
				
					// Reject error
					reject(error);
				});
			});
		});
	}
}

// USB transport
class UsbTransport {

	// Constructor
	constructor(device) {
	
		// Set device
		this.device = device;
	}
	
	// Send
	send(type, data, allowedResponseType) {
	
		// Set self
		const self = this;
	
		// Return promise
		return new Promise(function(resolve, reject) {
		
			// Encoded the data
			const encodedData = (type.toFixed() in HardwareWalletDefinitions.SCHEMA === true) ? ProtocolBuffers.encode(type, data, HardwareWalletDefinitions.SCHEMA) : new Uint8Array([]);
			
			// Create payload
			const payload = Buffer.alloc(Uint16Array["BYTES_PER_ELEMENT"] + Uint32Array["BYTES_PER_ELEMENT"] + encodedData["length"]);
			payload.writeUint16BE(type);
			payload.writeUint32BE(encodedData["length"], Uint16Array["BYTES_PER_ELEMENT"]);
			Buffer.from(encodedData).copy(payload, Uint16Array["BYTES_PER_ELEMENT"] + Uint32Array["BYTES_PER_ELEMENT"]);
			
			// Create packets
			const packets = createPackets(payload);
			
			// Send packet
			let sendPacket = new Promise(function(resolve, reject) {
			
				// Resolve
				resolve();
			});
			
			// Initialize sending packets
			const sendingPackets = [sendPacket];
			
			// Go through all packets
			for(let i = 0; i < packets["length"]; ++i) {
			
				// Get packet
				let packet = packets[i];
				
				// Send next pack after previous packet is send
				sendPacket = sendPacket.then(function() {
				
					// Return promise
					return new Promise(function(resolve, reject) {
			
						// Return sending packet
						return self.device.transferOut(1, packet).then(function() {
						
							// Resolve
							resolve();
							
						// Catch errors
						}).catch(function(error) {
						
							// Reject error
							reject(error);
						});
					});
						
				// Catch errors
				}).catch(function(error) {
				
					// Return promise
					return new Promise(function(resolve, reject) {
					
						// Reject error
						reject(error);
					});
				});
				
				// Append sending packet to list
				sendingPackets.push(sendPacket);
			}
			
			// Return sending all packets
			return Promise.all(sendingPackets).then(function() {
			
				// Receive packet
				const receivePacket = function(firstPacket) {
				
					// Return promise
					return new Promise(function(resolve, reject) {
					
						// Return transfering in packet
						return self.device.transferIn(1, PACKET_SIZE).then(function(response) {
						
							// Get packet from response
							const packet = Buffer.from(response["data"]["buffer"]);
							
							// Check if packet's size is correct
							if(packet["length"] === PACKET_SIZE) {
							
								// Check if at the first packet
								if(firstPacket === true) {
								
									// Check if packet's is invalid
									if(packet.toString("utf8", 0, "?##"["length"]) !== "?##") {
									
										// Reject
										reject();
									}
									
									// Otherwise
									else {
									
										// Resolve packet's payload
										resolve(packet.subarray("?##"["length"]));
									}
								}
								
								// Otherwise
								else {
								
									// Check if packet's is invalid
									if(packet.toString("utf8", 0, "?"["length"]) !== "?") {
									
										// Reject
										reject();
									}
									
									// Otherwise
									else {
									
										// Resolve packet's payload
										resolve(packet.subarray("?"["length"]));
									}
								}
							}
								
							// Otherwise
							else {
							
								// Reject
								reject();
							}
							
						// Catch errors
						}).catch(function(error) {
						
							// Reject error
							reject(error);
						});
					});
				};
				
				// Return receiving first packet
				return receivePacket(true).then(function(responsePart) {
				
					// Get response type
					const responseType = responsePart.readUint16BE();
					
					// Get length
					const length = responsePart.readUint32BE(Uint16Array["BYTES_PER_ELEMENT"]);
					
					// Set response
					let response = responsePart.subarray(Uint16Array["BYTES_PER_ELEMENT"] + Uint32Array["BYTES_PER_ELEMENT"]);
					
					// Get next response part
					const getNextResponsePart = function() {
					
						// Return promise
						return new Promise(function(resolve, reject) {
						
							// Check if the entire response hasn't been received
							if(response["length"] < length) {
							
								// Return receiving next packet
								return receivePacket(false).then(function(responsePart) {
								
									// Append response part to response
									response = Buffer.concat([response, responsePart]);
									
									// Return getting next response part
									return getNextResponsePart().then(function() {
									
										// Resolve
										resolve();
										
									// Catch errors
									}).catch(function(error) {
									
										// Reject error
										reject(error);
									});
									
								// Catch errors
								}).catch(function(error) {
								
									// Reject error
									reject(error);
								});
							}
							
							// Otherwise
							else {
							
								// Resolve
								resolve();
							}
						});
					};
					
					// Return getting next response part
					return getNextResponsePart().then(function() {
					
						// Check if response type isn't allowed and isn't requesting a button be pressed, a passphrase to be provided, or a pin matrix to be provided and response isn't a failure response to a pin matrix
						if(responseType !== allowedResponseType && responseType !== HardwareWalletDefinitions.TREZOR_BUTTON_REQUEST_MESSAGE_TYPE && responseType !== HardwareWalletDefinitions.TREZOR_PASSPHRASE_REQUEST_MESSAGE_TYPE && responseType !== HardwareWalletDefinitions.TREZOR_PIN_MATRIX_REQUEST_MESSAGE_TYPE && (type !== HardwareWalletDefinitions.TREZOR_PIN_MATRIX_ACKNOWLEDGE_MESSAGE_TYPE || responseType !== HardwareWalletDefinitions.TREZOR_FAILURE_MESSAGE_TYPE)) {
						
							// Check if response type is a failure response
							if(responseType === HardwareWalletDefinitions.TREZOR_FAILURE_MESSAGE_TYPE) {
						
								// Get failure from response
								const failure = ProtocolBuffers.decode(responseType, response.subarray(0, length), HardwareWalletDefinitions.SCHEMA);
								
								// Check if action or pin was canceled
								if(failure["Failure Type"].at(-1) === HardwareWalletDefinitions.TREZOR_ACTION_CANCELED_FAILURE_TYPE || failure["Failure Type"].at(-1) === HardwareWalletDefinitions.TREZOR_PIN_CANCELED_FAILURE_TYPE) {
								
									// Show message
									console.log("User canceled action on device");
								}
							}
							
							// Reject
							reject();
						}
						
						// Otherwise check if response is requesting a button be pressed
						else if(responseType === HardwareWalletDefinitions.TREZOR_BUTTON_REQUEST_MESSAGE_TYPE) {
						
							// Get button request from response
							const buttonRequest = ProtocolBuffers.decode(responseType, response.subarray(0, length), HardwareWalletDefinitions.SCHEMA);
							
							// Check if passphrase entry is requested
							if(buttonRequest["Button Request Type"].at(-1) === HardwareWalletDefinitions.TREZOR_PASSPHRASE_ENTRY_BUTTON_REQUEST_TYPE) {
							
								// Show message
								console.log("Enter passphrase on device");
							}
							
							// Check if pin entry is requested
							else if(buttonRequest["Button Request Type"].at(-1) === HardwareWalletDefinitions.TREZOR_PIN_ENTRY_BUTTON_REQUEST_TYPE) {
							
								// Show message
								console.log("Enter pin on device");
							}
						
							// Return sending button acknowledge request to the device
							return self.send(HardwareWalletDefinitions.TREZOR_BUTTON_ACKNOWLEDGE_MESSAGE_TYPE, {}, allowedResponseType).then(function(response) {
							
								// Resolve response
								resolve(response);
								
							// Catch errors
							}).catch(function(error) {
							
								// Reject error
								reject(error);
							});
						}
						
						// Otherwise check if response is requesting a passphrase to be provided
						else if(responseType === HardwareWalletDefinitions.TREZOR_PASSPHRASE_REQUEST_MESSAGE_TYPE) {
						
							// Return sending passphrase acknowledge request to the device
							return self.send(HardwareWalletDefinitions.TREZOR_PASSPHRASE_ACKNOWLEDGE_MESSAGE_TYPE, {
				
								// Passphrase
								"Passphrase": ""
								
							}, allowedResponseType).then(function(response) {
							
								// Resolve response
								resolve(response);
								
							// Catch errors
							}).catch(function(error) {
							
								// Reject error
								reject(error);
							});
						}
						
						// Otherwise check if response is requesting a pin matrix to be provided
						else if(responseType === HardwareWalletDefinitions.TREZOR_PIN_MATRIX_REQUEST_MESSAGE_TYPE) {
						
							// Create readline interface
							const readlineInterface = readline.createInterface({

								// Input
								"input": process.stdin,

								// Output
								"output": process.stdout
							});
						
							// Get pin
							readlineInterface.question("Enter pin: ", function(pin) {
							
								// Close readline interface
								readlineInterface.close();
								
								// Send pin matrix acknowledge request to the device
								self.send(HardwareWalletDefinitions.TREZOR_PIN_MATRIX_ACKNOWLEDGE_MESSAGE_TYPE, {
					
									// Pin
									"Pin": pin
									
								}, allowedResponseType).then(function(response) {
								
									// Resolve response
									resolve(response);
									
								// Catch errors
								}).catch(function(error) {
								
									// Reject error
									reject(error);
								});
							});
						}
						
						// Otherwise check if response is failure response to a pin matrix
						else if(type === HardwareWalletDefinitions.TREZOR_PIN_MATRIX_ACKNOWLEDGE_MESSAGE_TYPE && responseType === HardwareWalletDefinitions.TREZOR_FAILURE_MESSAGE_TYPE) {
						
							// Get failure from response
							const failure = ProtocolBuffers.decode(responseType, response.subarray(0, length), HardwareWalletDefinitions.SCHEMA);
							
							// Check if pin is invalid
							if(failure["Failure Type"].at(-1) === HardwareWalletDefinitions.TREZOR_PIN_CANCELED_FAILURE_TYPE || failure["Failure Type"].at(-1) === HardwareWalletDefinitions.TREZOR_PIN_INVALID_FAILURE_TYPE) {
							
								// Show message
								console.log("Invalid pin");
							}
							
							// Reject
							reject();
						}
						
						// Otherwise
						else {
					
							// Try
							try {
							
								// Decode response
								var decodedResponse = ProtocolBuffers.decode(responseType, response.subarray(0, length), HardwareWalletDefinitions.SCHEMA);
							}
							
							// Catch errors
							catch(error) {
							
								// Reject error
								reject(error);
								
								// Return
								return;
							}
							
							// Resolve decoded response
							resolve(decodedResponse);
						}
					
					// Catch errors
					}).catch(function(error) {
					
						// Reject error
						reject(error);
					});
					
				// Catch errors
				}).catch(function(error) {
				
					// Reject error
					reject(error);
				});
				
			// Catch errors
			}).catch(function(error) {
			
				// Reject error
				reject(error);
			});
		});
	}

	// Get device
	static getDevice(vendorId, productId) {
	
		// Return promise
		return new Promise(function(resolve, reject) {
	
			// Require USB transport
			const webusb = require("usb")["webusb"];
			
			// Return getting device
			return webusb.requestDevice({
			
				// Filters
				"filters": [
					{
				
						// Vendor ID
						"vendorId": vendorId,
						
						// Product ID
						"productId": productId
					}
				]
				
			}).then(function(device) {
			
				// Return opening device
				return device.open().then(function() {
				
					// Return selecting configuration
					return device.selectConfiguration(1).then(function() {
					
						// Return reset device and catch errors
						return device.reset().catch(function() {
						
						// Finally
						}).finally(function() {
						
							// Return claiming interface
							return device.claimInterface(0).then(function() {
							
								// Create USB transport
								const usbTransport = new UsbTransport(device);
							
								// Resolve USB transport
								resolve(usbTransport);
							
							// Catch errors
							}).catch(function(error) {
							
								// Reject error
								reject(error);
							});
						});
					
					// Catch errors
					}).catch(function(error) {
					
						// Reject error
						reject(error);
					});
				
				// Catch errors
				}).catch(function(error) {
				
					// Reject error
					reject(error);
				});
			
			// Catch errors
			}).catch(function(error) {
			
				// Reject error
				reject(error);
			});
		});
	}
}


// Main fucntion
(async function() {

	// Check if loaded as a module
	if(require["main"] !== module) {
	
		// Return
		return;
	}
	
	// Get currency from the command line arguments if provided
	const currency = (process["argv"]["length"] >= 3) ? process["argv"][2] : DEFAULT_CURRENCY;
	
	// Check currency
	switch(currency) {
	
		// MimbleWimble Coin
		case "mimblewimble_coin":
		
			// Break
			break;
		
		// MimbleWimble Coin floonet
		case "mimblewimble_coin_floonet":
		
			// Set consensus's get network type
			Consensus.getNetworkType = function() {
			
				// Return testnet network type
				return Consensus.TESTNET_NETWORK_TYPE;
			};
		
			// Break
			break;
		
		// Grin
		case "grin":
		
			// Set consensus's get wallet type
			Consensus.getWalletType = function() {
			
				// Return Grin wallet type
				return Consensus.GRIN_WALLET_TYPE;
			};
		
			// Break
			break;
		
		// Grin testnet
		case "grin_testnet":
		
			// Set consensus's get wallet type
			Consensus.getWalletType = function() {
			
				// Return Grin wallet type
				return Consensus.GRIN_WALLET_TYPE;
			};
			
			// Set consensus's get netwotk type
			Consensus.getNetworkType = function() {
			
				// Return testnet network type
				return Consensus.TESTNET_NETWORK_TYPE;
			};
		
			// Break
			break;
		
		// Epic Cash
		case "epic_cash":
		
			// Set consensus's get wallet type
			Consensus.getWalletType = function() {
			
				// Return Epic Cash wallet type
				return Consensus.EPIC_WALLET_TYPE;
			};
		
			// Break
			break;
		
		// Epic Cash floonet
		case "epic_cash_floonet":
		
			// Set consensus's get wallet type
			Consensus.getWalletType = function() {
			
				// Return Epic Cash wallet type
				return Consensus.EPIC_WALLET_TYPE;
			};
			
			// Set consensus's get netwotk type
			Consensus.getNetworkType = function() {
			
				// Return testnet network type
				return Consensus.TESTNET_NETWORK_TYPE;
			};
		
			// Break
			break;
		
		// Default
		default:
		
			// Log message
			console.log("Invalid currency. Supported currencies are: mimblewimble_coin, mimblewimble_coin_floonet, grin, grin_testnet, epic_cash, and epic_cash_floonet");
			
			// Return
			return;
	}
	
	// Get use emulator from the command line arguments if provided
	const useEmulator = process["argv"]["length"] >= 4 && process["argv"][3] === "emulator";
	
	// Log message
	console.log("Using currency: " + currency);

	// Initialize dependencies
	await initializeDependencies();
	
	// Perform tests
	await performTests(useEmulator);
})();


// Supporting function implementation

// Initialize dependencies
async function initializeDependencies() {

	// Initialize BLAKE2b
	await Blake2b.initialize();
	
	// Initialize Ed25519
	await Ed25519.initialize();
	
	// Initialize X25519
	await X25519.initialize();
	
	// Initialize secp256k1-zkp
	await Secp256k1Zkp.initialize();
}

// Perform tests
async function performTests(useEmulator) {
	
	// Try
	try {
	
		// Check if using emulator
		if(useEmulator === true) {
		
			// Connect to the hardware wallet using emulator
			var hardwareWallet = new EmulatorTransport(EMULATOR_ADDRESS, EMULATOR_PORT);
		}
		
		// Otherwise
		else {
		
			// Connect to the hardware wallet using USB
			var hardwareWallet = await UsbTransport.getDevice(USB_VENDOR_ID, USB_PRODUCT_ID);
		}
		
		// Log message
		console.log("Running functional tests with the mnemonic: " + MNEMONIC);
		
		// Log message
		console.log("Running functional tests with the account: " + ACCOUNT.toFixed());
		
		// Log message
		console.log("Running functional tests with the index: " + INDEX.toFixed());
		
		// Initialize seed
		const seed = new Seed();
		await seed.initialize(MNEMONIC);
		
		// Get the extended private key from the seed
		const extendedPrivateKey = await seed.getExtendedPrivateKey(SEED_KEY, true);
		
		// Run get application information test
		await getApplicationInformationTest(hardwareWallet);
		
		// Run get root public key test
		await getRootPublicKeyTest(hardwareWallet, extendedPrivateKey);
		
		// Check if using MimbleWimble Coin
		if(Consensus.getWalletType() === Consensus.MWC_WALLET_TYPE) {
		
			// Run get address test
			await getAddressTest(hardwareWallet, extendedPrivateKey, MQS_ADDRESS_TYPE);
			await getAddressTest(hardwareWallet, extendedPrivateKey, TOR_ADDRESS_TYPE);
		}
		
		// Otherwise check if using Grin
		else if(Consensus.getWalletType() === Consensus.GRIN_WALLET_TYPE) {
		
			// Run get address test
			await getAddressTest(hardwareWallet, extendedPrivateKey, SLATEPACK_ADDRESS_TYPE);
		}
		
		// Otherwise check if using Epic Cash
		else if(Consensus.getWalletType() === Consensus.EPIC_WALLET_TYPE) {
		
			// Run get address test
			await getAddressTest(hardwareWallet, extendedPrivateKey, MQS_ADDRESS_TYPE);
			await getAddressTest(hardwareWallet, extendedPrivateKey, TOR_ADDRESS_TYPE);
		}
		
		// Run get seed cookie test
		await getSeedCookieTest(hardwareWallet, extendedPrivateKey);
		
		// Run get commitment test
		await getCommitmentTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR);
		
		// Run get bulletproof test
		await getBulletproofTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SENDING_TRANSACTION_MESSAGE_TYPE);
		await getBulletproofTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, RECEIVING_TRANSACTION_MESSAGE_TYPE);
		await getBulletproofTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, CREATING_COINBASE_MESSAGE_TYPE);
		
		// Run verify root public key test
		await verifyRootPublicKeyTest(hardwareWallet, extendedPrivateKey);
		
		// Check if using MimbleWimble Coin
		if(Consensus.getWalletType() === Consensus.MWC_WALLET_TYPE) {
		
			// Run verify address test
			await verifyAddressTest(hardwareWallet, extendedPrivateKey, MQS_ADDRESS_TYPE);
			await verifyAddressTest(hardwareWallet, extendedPrivateKey, TOR_ADDRESS_TYPE);
		}
		
		// Otherwise check if using Grin
		else if(Consensus.getWalletType() === Consensus.GRIN_WALLET_TYPE) {
		
			// Run verify address test
			await verifyAddressTest(hardwareWallet, extendedPrivateKey, SLATEPACK_ADDRESS_TYPE);
		}
		
		// Otherwise check if using Epic Cash
		else if(Consensus.getWalletType() === Consensus.EPIC_WALLET_TYPE) {
		
			// Run verify address test
			await verifyAddressTest(hardwareWallet, extendedPrivateKey, MQS_ADDRESS_TYPE);
			await verifyAddressTest(hardwareWallet, extendedPrivateKey, TOR_ADDRESS_TYPE);
		}
		
		// Check if using MimbleWimble Coin
		if(Consensus.getWalletType() === Consensus.MWC_WALLET_TYPE) {
		
			// Run encrypt slate test
			await encryptSlateTest(hardwareWallet, extendedPrivateKey, MQS_ADDRESS_TYPE);
			await encryptSlateTest(hardwareWallet, extendedPrivateKey, TOR_ADDRESS_TYPE);
		}
		
		// Otherwise check if using Epic Cash
		else if(Consensus.getWalletType() === Consensus.EPIC_WALLET_TYPE) {
		
			// Run encrypt slate test
			await encryptSlateTest(hardwareWallet, extendedPrivateKey, MQS_ADDRESS_TYPE);
		}
		
		// Check if using MimbleWimble Coin
		if(Consensus.getWalletType() === Consensus.MWC_WALLET_TYPE) {
		
			// Run decrypt slate test
			await decryptSlateTest(hardwareWallet, extendedPrivateKey, MQS_ADDRESS_TYPE);
			await decryptSlateTest(hardwareWallet, extendedPrivateKey, TOR_ADDRESS_TYPE);
		}
		
		// Otherwise check if using Grin
		else if(Consensus.getWalletType() === Consensus.GRIN_WALLET_TYPE) {
		
			// Run decrypt slate test
			await decryptSlateTest(hardwareWallet, extendedPrivateKey, SLATEPACK_ADDRESS_TYPE);
		}
		
		// Otherwise check if using Epic Cash
		else if(Consensus.getWalletType() === Consensus.EPIC_WALLET_TYPE) {
		
			// Run decrypt slate test
			await decryptSlateTest(hardwareWallet, extendedPrivateKey, MQS_ADDRESS_TYPE);
		}
		
		// Check if using MimbleWimble Coin
		if(Consensus.getWalletType() === Consensus.MWC_WALLET_TYPE) {
		
			// Run receive transaction test
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.COINBASE_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, MQS_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.COINBASE_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, MQS_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, MQS_ADDRESS_TYPE, MQS_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, MQS_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, MQS_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, MQS_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, MQS_ADDRESS_TYPE, MQS_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, MQS_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, MQS_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), MQS_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), MQS_ADDRESS_TYPE, MQS_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), MQS_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), TOR_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), TOR_ADDRESS_TYPE, MQS_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), TOR_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
		}
		
		// Otherwise check if using Grin
		else if(Consensus.getWalletType() === Consensus.GRIN_WALLET_TYPE) {
		
			// Run receive transaction test
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.COINBASE_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, SLATEPACK_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, SLATEPACK_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, SLATEPACK_ADDRESS_TYPE, SLATEPACK_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, SLATEPACK_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, SLATEPACK_ADDRESS_TYPE, SLATEPACK_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), SLATEPACK_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), SLATEPACK_ADDRESS_TYPE, SLATEPACK_PAYMENT_PROOF_TYPE);
		}
		
		// Otherwise check if using Epic Cash
		else if(Consensus.getWalletType() === Consensus.EPIC_WALLET_TYPE) {
		
			// Run receive transaction test
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.COINBASE_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await receiveTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
		}
		
		// Check if using MimbleWimble Coin
		if(Consensus.getWalletType() === Consensus.MWC_WALLET_TYPE) {
		
			// Run send transaction test
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, MQS_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, MQS_ADDRESS_TYPE, MQS_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, MQS_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, MQS_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, MQS_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, MQS_ADDRESS_TYPE, MQS_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, MQS_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, MQS_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), MQS_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), MQS_ADDRESS_TYPE, MQS_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), MQS_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), TOR_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), TOR_ADDRESS_TYPE, MQS_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), TOR_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
		}
		
		// Otherwise check if using Grin
		else if(Consensus.getWalletType() === Consensus.GRIN_WALLET_TYPE) {
		
			// Run send transaction test
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, SLATEPACK_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, SLATEPACK_ADDRESS_TYPE, SLATEPACK_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, SLATEPACK_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, SLATEPACK_ADDRESS_TYPE, SLATEPACK_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), SLATEPACK_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.NO_RECENT_DUPLICATE_FEATURES, Slate.NO_LOCK_HEIGHT, new BigNumber(Math.floor(Math.random() * (SlateKernel.MAXIMUM_RECENT_HEIGHT - SlateKernel.MINIMUM_RECENT_HEIGHT + 1)) + SlateKernel.MINIMUM_RECENT_HEIGHT), SLATEPACK_ADDRESS_TYPE, SLATEPACK_PAYMENT_PROOF_TYPE);
		}
		
		// Otherwise check if using Epic Cash
		else if(Consensus.getWalletType() === Consensus.EPIC_WALLET_TYPE) {
		
			// Run send transaction test
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.PLAIN_FEATURES, Slate.NO_LOCK_HEIGHT, SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, NO_PAYMENT_PROOF_TYPE);
			await sendTransactionTest(hardwareWallet, extendedPrivateKey, Crypto.SWITCH_TYPE_REGULAR, SlateKernel.HEIGHT_LOCKED_FEATURES, new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER)), SlateKernel.NO_RELATIVE_HEIGHT, TOR_ADDRESS_TYPE, TOR_PAYMENT_PROOF_TYPE);
		}
		
		// Check if using MimbleWimble Coin
		if(Consensus.getWalletType() === Consensus.MWC_WALLET_TYPE) {
		
			// Run get MQS timestamp signature test
			await getMqsTimestampSignatureTest(hardwareWallet, extendedPrivateKey);
		}
		
		// Otherwise check if using Epic Cash
		else if(Consensus.getWalletType() === Consensus.EPIC_WALLET_TYPE) {
		
			// Run get MQS timestamp signature test
			await getMqsTimestampSignatureTest(hardwareWallet, extendedPrivateKey);
		}
		
		// Check if using MimbleWimble Coin
		if(Consensus.getWalletType() === Consensus.MWC_WALLET_TYPE) {
		
			// Run get MQS default challenge signature test
			await getMqsDefaultChallengeSignatureTest(hardwareWallet, extendedPrivateKey);
		}
		
		// Otherwise check if using Epic Cash
		else if(Consensus.getWalletType() === Consensus.EPIC_WALLET_TYPE) {
		
			// Run get MQS default challenge signature test
			await getMqsDefaultChallengeSignatureTest(hardwareWallet, extendedPrivateKey);
		}
		
		// Run get login signature test
		await getLoginSignatureTest(hardwareWallet, extendedPrivateKey);
		
		// Log message
		console.log("Passed running all functional tests");
		
		// Exit with success
		process.exit(0);
	}
	
	// Catch errors
	catch(error) {
	
		// Log error
		console.log(error);
		
		// Log message
		console.log("Running functional tests failed");
		
		// Exit with error
		process.exit(1);
	}
}

// Create packets
function createPackets(payload) {

	// Initialize packets
	const packets = [];
	
	// Check if more than one packet will be used
	if(payload["length"] > PACKET_SIZE - 3) {
	
		// Create padded payload
		const numberOfPackets = Math.ceil((payload["length"] - (PACKET_SIZE - "?##"["length"])) / (PACKET_SIZE - "?"["length"]));
		var paddedPayload = (new Uint8Array(PACKET_SIZE - "?##"["length"] + numberOfPackets * (PACKET_SIZE - "?"["length"]))).fill(0);
		paddedPayload.set(payload);
	}
	
	// Otherwise
	else {
	
		// Create padded payload
		var paddedPayload = (new Uint8Array(PACKET_SIZE - "?##"["length"])).fill(0);
		paddedPayload.set(payload);
	}
	
	// Initialize offset
	let offset = 0;
	
	// Go through all packets required to send the padded payload
	for(let i = 0; offset !== paddedPayload["length"]; ++i) {
	
		// Check if at the first packet
		if(i === 0) {
		
			// Create header
			var header = (new TextEncoder()).encode("?##");
		}
		
		// Otherwise
		else {
	
			// Create header
			var header = (new TextEncoder()).encode("?");
		}
		
		// Get part length
		const partLength = PACKET_SIZE - header["length"];
		
		// Create packet
		const packet = new Uint8Array(header["length"] + partLength);
		packet.set(header);
		packet.set(paddedPayload.subarray(offset, offset + partLength), header["length"]);
		
		// Append packet to list
		packets.push(packet);
		
		// Update offset
		offset += partLength;
	}
	
	// Return packets
	return packets;
}

// Get application information test
async function getApplicationInformationTest(hardwareWallet) {

	// Log message
	console.log("Running get application information test");
	
	// Get features from the hardware wallet
	const features = await hardwareWallet.send(HardwareWalletDefinitions.TREZOR_INITIALIZE_MESSAGE_TYPE, {}, HardwareWalletDefinitions.TREZOR_FEATURES_MESSAGE_TYPE);
	
	// Check if firmware doesn't have a version
	if("Major Version" in features === false || "Minor Version" in features === false || "Patch Version" in features === false) {
	
		// Throw error
		throw "Device is in bootloader mode.";
	}
	
	// Get firmware version
	const firmwareVersion = features["Major Version"].at(-1).toFixed() + "." + features["Minor Version"].at(-1).toFixed() + "." + features["Patch Version"].at(-1).toFixed();
	
	// Log firmware version
	console.log("Firmware version: " + firmwareVersion);
	
	// Log firmware capabilities
	console.log("Firmware capabilities: " + (("Capabilities" in features === false) ? "N/A" : features["Capabilities"].join(", ")));
	
	// Check if firmware isn't MimbleWimble Coin capable
	if("Capabilities" in features === false || features["Capabilities"].indexOf(MIMBLEWIMBLE_COIN_CAPABLE) === Common.INDEX_NOT_FOUND) {
	
		// Throw error
		throw "Firmware isn't MimbleWimble Coin capable.";
	}
	
	// Check if device isn't initialized
	if("Initialized" in features === false || features["Initialized"].at(-1) === false) {
	
		// Log message
		console.log("Confirm setting private seed on the device");
	
		// Set private seed on the hardware wallet
		await hardwareWallet.send(HardwareWalletDefinitions.TREZOR_LOAD_DEVICE_MESSAGE_TYPE, {
		
			// Mnemonic
			"Mnemonic": MNEMONIC,
			
			// Pin
			//"Pin": "1234"
			
		}, HardwareWalletDefinitions.TREZOR_SUCCESS_MESSAGE_TYPE);
		
		// Initialize the hardware wallet
		await hardwareWallet.send(HardwareWalletDefinitions.TREZOR_INITIALIZE_MESSAGE_TYPE, {}, HardwareWalletDefinitions.TREZOR_FEATURES_MESSAGE_TYPE);
	}
	
	/*// Apply settings to the hardware wallet
	await hardwareWallet.send(HardwareWalletDefinitions.TREZOR_APPLY_SETTINGS_MESSAGE_TYPE, {
	
		// Use passphrase
		"Use Passphrase": true,
		
		// Passphrase always on device
		"Passphrase Always On Device": true
		
	}, HardwareWalletDefinitions.TREZOR_SUCCESS_MESSAGE_TYPE);
	
	// Lock hardware wallet
	await hardwareWallet.send(HardwareWalletDefinitions.TREZOR_LOCK_DEVICE_MESSAGE_TYPE, {}, HardwareWalletDefinitions.TREZOR_SUCCESS_MESSAGE_TYPE);*/
	
	// Log message
	console.log("Passed getting application information test");
}

// Get root public key test
async function getRootPublicKeyTest(hardwareWallet, extendedPrivateKey) {

	// Log message
	console.log("Running get root public key test");
	
	// Get the expected root public key from the extended private key
	const expectedRootPublicKey = await Crypto.rootPublicKey(extendedPrivateKey);
	
	// Log message
	console.log("Verify that the account index on the device is: " + ACCOUNT.toFixed());
	
	// Get the root public key from the hardware wallet
	const rootPublicKey = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_GET_ROOT_PUBLIC_KEY_MESSAGE_TYPE, {
	
		// Coin type
		"Coin Type": Consensus.getWalletType(),
		
		// Network type
		"Network Type": Consensus.getNetworkType(),
		
		// Account
		"Account": ACCOUNT
		
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_ROOT_PUBLIC_KEY_MESSAGE_TYPE))["Root Public Key"].at(-1);
		
	// Log root public key
	console.log("Root public key: " + Common.toHexString(rootPublicKey));
	
	// Check if root public key is invalid
	if(Common.arraysAreEqual(rootPublicKey, expectedRootPublicKey) === false) {
	
		// Log message
		console.log("Invalid root public key");
	
		// Throw error
		throw "Failed running get root pubic key test";
	}
	
	// Log message
	console.log("Passed getting root pubic key test");
}

// Get address test
async function getAddressTest(hardwareWallet, extendedPrivateKey, addressType) {

	// Log message
	console.log("Running get address test");
	
	// Check address type
	switch(addressType) {
	
		// MQS address type
		case MQS_ADDRESS_TYPE:
		
			// Log message
			console.log("Using address type: MQS");
			
			// Get MQS private key from the extended private key
			const mqsPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get MQS public key from the MQS private key
			const mqsPublicKey = Secp256k1Zkp.publicKeyFromSecretKey(mqsPrivateKey);
			
			// Get expected address from the MQS public key
			var expectedAddress = Mqs.publicKeyToMqsAddress(mqsPublicKey, Consensus.getNetworkType() === Consensus.MAINNET_NETWORK_TYPE);
			
			// Break
			break;
		
		// Tor address type
		case TOR_ADDRESS_TYPE:
		
			// Log message
			console.log("Using address type: Tor");
			
			// Get Tor private key from the extended private key
			const torPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get Tor public key from the Tor private key
			const torPublicKey = Ed25519.publicKeyFromSecretKey(torPrivateKey);
			
			// Get expected address from the Tor public key
			var expectedAddress = Tor.publicKeyToTorAddress(torPublicKey);
			
			// Break
			break;
		
		// Slatepack address type
		case SLATEPACK_ADDRESS_TYPE:
		
			// Log message
			console.log("Using address type: Slatepack");
			
			// Get Slatepack private key from the extended private key
			const slatepackPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get Slatepack public key from the Slatepack private key
			const slatepackPublicKey = Ed25519.publicKeyFromSecretKey(slatepackPrivateKey);
			
			// Get expected address from the Slatepack public key
			var expectedAddress = Slatepack.publicKeyToSlatepackAddress(slatepackPublicKey);
			
			// Break
			break;
	}
	
	// Get the address from the hardware wallet
	const address = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_GET_ADDRESS_MESSAGE_TYPE, {
	
		// Coin type
		"Coin Type": Consensus.getWalletType(),
		
		// Network type
		"Network Type": Consensus.getNetworkType(),
		
		// Address type
		"Parameter One": addressType,
		
		// Account
		"Account": ACCOUNT,
		
		// Index
		"Index": INDEX
		
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_ADDRESS_MESSAGE_TYPE))["Address"].at(-1);
	
	// Log address
	console.log("Address: " + address);
	
	// Check if address is invalid
	if(address !== expectedAddress) {
	
		// Log message
		console.log("Invalid address");
		
		// Throw error
		throw "Failed running get address test";
	}
	
	// Log message
	console.log("Passed getting address test");
}

// Get seed cookie test
async function getSeedCookieTest(hardwareWallet, extendedPrivateKey) {

	// Log message
	console.log("Running get seed cookie test");
	
	// Get the root public key from the extended private key
	const rootPublicKey = await Crypto.rootPublicKey(extendedPrivateKey);
	
	// Get the expected seed cookie from the root public key
	const expectedSeedCookie = new Uint8Array(await crypto["subtle"].digest("SHA-512", rootPublicKey));
	
	// Get the seed cookie from the hardware wallet
	const seedCookie = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_GET_SEED_COOKIE_MESSAGE_TYPE, {
	
		// Coin type
		"Coin Type": Consensus.getWalletType(),
		
		// Network type
		"Network Type": Consensus.getNetworkType(),
		
		// Account
		"Account": ACCOUNT
		
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_SEED_COOKIE_MESSAGE_TYPE))["Seed Cookie"].at(-1);
	
	// Log seed cookie
	console.log("Seed cookie: " + Common.toHexString(seedCookie));
	
	// Check if seed cookie is invalid
	if(Common.arraysAreEqual(seedCookie, expectedSeedCookie) === false) {
	
		// Log message
		console.log("Invalid seed cookie");
		
		// Throw error
		throw "Failed running get seed cookie test";
	}
	
	// Log message
	console.log("Passed getting seed cookie test");
}

// Get commitment test
async function getCommitmentTest(hardwareWallet, extendedPrivateKey, switchType) {

	// Log message
	console.log("Running get commitment test");
	
	// Amount
	const AMOUNT = new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER));
	
	// Identifier
	const IDENTIFIER = new Identifier(Common.toHexString(Common.mergeArrays([new Uint8Array([Math.round(Math.random() * Identifier.MAX_DEPTH)]), crypto.getRandomValues(new Uint8Array(Identifier.MAX_DEPTH * Uint32Array["BYTES_PER_ELEMENT"]))])));
	
	// Log amount
	console.log("Using amount: " + AMOUNT.toFixed());
	
	// Log identifier
	console.log("Using identifier: " + Common.toHexString(IDENTIFIER.getValue()));
	
	// Check switch type
	switch(switchType) {
	
		// Switch type none
		case Crypto.SWITCH_TYPE_NONE:
		
			// Log switch type
			console.log("Using switch type: none");
		
			// Break
			break;
		
		// Regular switch type
		case Crypto.SWITCH_TYPE_REGULAR:
		
			// Log switch type
			console.log("Using switch type: regular");
		
			// Break
			break;
	}
	
	// Get the expected commitment from the extended private key, amount, identifier, and switch type
	const expectedCommitment = await Crypto.commit(extendedPrivateKey, AMOUNT, IDENTIFIER, switchType);
	
	// Get commitment from the hardware wallet
	const commitment = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_GET_COMMITMENT_MESSAGE_TYPE, {
				
		// Coin type
		"Coin Type": Consensus.getWalletType(),
		
		// Network type
		"Network Type": Consensus.getNetworkType(),
		
		// Account
		"Account": ACCOUNT,
		
		// Identifier
		"Identifier": IDENTIFIER.getValue(),
		
		// Value
		"Value": AMOUNT,
		
		// Switch type
		"Switch Type": switchType
	
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_COMMITMENT_MESSAGE_TYPE))["Commitment"].at(-1);
	
	// Log commitment
	console.log("Commitment: " + Common.toHexString(commitment));
	
	// Check if commitment is invalid
	if(Common.arraysAreEqual(commitment, expectedCommitment) === false) {
	
		// Log message
		console.log("Invalid commitment");
		
		// Throw error
		throw "Failed running get commitment test";
	}
	
	// Log message
	console.log("Passed getting commitment test");
}

// Get bulletproof test
async function getBulletproofTest(hardwareWallet, extendedPrivateKey, switchType, messageType) {

	// Log message
	console.log("Running get bulletproof test");
	
	// Amount
	const AMOUNT = new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER));
	
	// Identifier
	const IDENTIFIER = new Identifier(Common.toHexString(Common.mergeArrays([new Uint8Array([Math.round(Math.random() * Identifier.MAX_DEPTH)]), crypto.getRandomValues(new Uint8Array(Identifier.MAX_DEPTH * Uint32Array["BYTES_PER_ELEMENT"]))])));
	
	// Log amount
	console.log("Using amount: " + AMOUNT.toFixed());
	
	// Log identifier
	console.log("Using identifier: " + Common.toHexString(IDENTIFIER.getValue()));
	
	// Check switch type
	switch(switchType) {
	
		// Switch type none
		case Crypto.SWITCH_TYPE_NONE:
		
			// Log switch type
			console.log("Using switch type: none");
		
			// Break
			break;
		
		// Regular switch type
		case Crypto.SWITCH_TYPE_REGULAR:
		
			// Log switch type
			console.log("Using switch type: regular");
		
			// Break
			break;
	}
	
	// Initialize proof builder with the extended private key
	const proofBuilder = new NewProofBuilder();
	await proofBuilder.initialize(extendedPrivateKey);
	
	// Get expected bulletproof from the extended private key, amount, identifier, switch type, and proof builder
	const expectedBulletproof = await Crypto.proof(extendedPrivateKey, AMOUNT, IDENTIFIER, switchType, proofBuilder);
	
	// Get bulletproof components from the hardware wallet
	const response = await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_GET_BULLETPROOF_COMPONENTS_MESSAGE_TYPE, {
				
		// Coin type
		"Coin Type": Consensus.getWalletType(),
		
		// Network type
		"Network Type": Consensus.getNetworkType(),
		
		// Message type
		"Parameter One": messageType,
		
		// Account
		"Account": ACCOUNT,
		
		// Identifier
		"Identifier": IDENTIFIER.getValue(),
		
		// Value
		"Value": AMOUNT,
		
		// Switch type
		"Switch Type": switchType
	
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_BULLETPROOF_COMPONENTS_MESSAGE_TYPE);
	
	// Get tau x from response
	const tauX = response["Tau X"].at(-1);
	
	// Get t one from response
	const tOne = response["T One"].at(-1);
	
	// Get t two from response
	const tTwo = response["T Two"].at(-1);
	
	// Get commitment from the extended private key, amount, identifier, and switch type
	const commitment = await Crypto.commit(extendedPrivateKey, AMOUNT, IDENTIFIER, switchType);
	
	// Get rewind nonce from the proof builder and the commitment
	const rewindNonce = await proofBuilder.rewindNonce(commitment);
	
	// Get proof message from identifier and switch type
	const proofMessage = proofBuilder.proofMessage(IDENTIFIER, switchType);
	
	// Create bulletproof with the tau x, t one, t two, commit, amount, rewind nonce, and proof message
	const bulletproof = Secp256k1Zkp.createBulletproofBlindless(tauX, tOne, tTwo, commitment, AMOUNT.toFixed(), rewindNonce, new Uint8Array([]), proofMessage);
	
	// Log commitment
	console.log("Bulletproof: " + Common.toHexString(bulletproof));
	
	// Check if commitment is invalid
	if(Common.arraysAreEqual(bulletproof, expectedBulletproof) === false) {
	
		// Log message
		console.log("Invalid bulletproof");
		
		// Throw error
		throw "Failed running get bulletproof test";
	}
	
	// Log message
	console.log("Passed getting bulletproof test");
}

// Verify root public key test
async function verifyRootPublicKeyTest(hardwareWallet, extendedPrivateKey) {

	// Log message
	console.log("Running verify root public key test");
	
	// Get the root public key from the extended private key
	const rootPublicKey = await Crypto.rootPublicKey(extendedPrivateKey);
	
	// Log message
	console.log("Verify that the root public key on the device is: " + Common.toHexString(rootPublicKey));
	
	// Verify root public key on the hardware wallet
	await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_VERIFY_ROOT_PUBLIC_KEY_MESSAGE_TYPE, {
	
		// Coin type
		"Coin Type": Consensus.getWalletType(),
		
		// Network type
		"Network Type": Consensus.getNetworkType(),
		
		// Account
		"Account": ACCOUNT
		
	}, HardwareWalletDefinitions.TREZOR_SUCCESS_MESSAGE_TYPE);
	
	// Log message
	console.log("Passed verifying root pubic key test");
}

// Verify address test
async function verifyAddressTest(hardwareWallet, extendedPrivateKey, addressType) {

	// Log message
	console.log("Running verify address test");
	
	// Check address type
	switch(addressType) {
	
		// MQS address type
		case MQS_ADDRESS_TYPE:
		
			// Log message
			console.log("Using address type: MQS");
			
			// Get MQS private key from the extended private key
			const mqsPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get MQS public key from the MQS private key
			const mqsPublicKey = Secp256k1Zkp.publicKeyFromSecretKey(mqsPrivateKey);
			
			// Get address from the MQS public key
			var address = Mqs.publicKeyToMqsAddress(mqsPublicKey, Consensus.getNetworkType() === Consensus.MAINNET_NETWORK_TYPE);
			
			// Check if using MimbleWimble Coin
			if(Consensus.getWalletType() === Consensus.MWC_WALLET_TYPE) {
		
				// Log message
				console.log("Verify that the MQS address on the device is: " + address);
			}
			
			// Otherwise check if using Epic Cash
			else if(Consensus.getWalletType() === Consensus.EPIC_WALLET_TYPE) {
			
				// Log message
				console.log("Verify that the Epicbox address on the device is: " + address);
			}
			
			// Break
			break;
		
		// Tor address type
		case TOR_ADDRESS_TYPE:
		
			// Log message
			console.log("Using address type: Tor");
			
			// Get Tor private key from the extended private key
			const torPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get Tor public key from the Tor private key
			const torPublicKey = Ed25519.publicKeyFromSecretKey(torPrivateKey);
			
			// Get address from the Tor public key
			var address = Tor.publicKeyToTorAddress(torPublicKey);
			
			// Log message
			console.log("Verify that the Tor address on the device is: " + address);
			
			// Break
			break;
		
		// Slatepack address type
		case SLATEPACK_ADDRESS_TYPE:
		
			// Log message
			console.log("Using address type: Slatepack");
			
			// Get Slatepack private key from the extended private key
			const slatepackPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get Slatepack public key from the Slatepack private key
			const slatepackPublicKey = Ed25519.publicKeyFromSecretKey(slatepackPrivateKey);
			
			// Get address from the Slatepack public key
			var address = Slatepack.publicKeyToSlatepackAddress(slatepackPublicKey);
			
			// Log message
			console.log("Verify that the Slatepack address on the device is: " + address);
			
			// Break
			break;
	}
	
	// Verify address on the hardware wallet
	await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_VERIFY_ADDRESS_MESSAGE_TYPE, {
	
		// Coin type
		"Coin Type": Consensus.getWalletType(),
		
		// Network type
		"Network Type": Consensus.getNetworkType(),
		
		// Address type
		"Parameter One": addressType,
		
		// Account
		"Account": ACCOUNT,
		
		// Index
		"Index": INDEX
		
	}, HardwareWalletDefinitions.TREZOR_SUCCESS_MESSAGE_TYPE);
	
	// Log message
	console.log("Passed verifying address test");
}

// Encrypt slate test
async function encryptSlateTest(hardwareWallet, extendedPrivateKey, addressType) {

	// Log message
	console.log("Running encrypt slate test");
	
	// Data
	const DATA = crypto.getRandomValues(new Uint8Array(Math.round(Math.random() * Common.BYTE_MAX_VALUE + 1)));
	
	// Maximum chunk size
	const MAXIMUM_CHUNK_SIZE = 64;
	
	// Domain
	const DOMAIN = "example.com";
	
	// Port
	const PORT = 80;
	
	// Log data
	console.log("Using data: " + Common.toHexString(DATA));
	
	// While random private key isn't a valid secret key
	const privateKey = new Uint8Array(Crypto.SECP256K1_SECRET_KEY_LENGTH);
	do {
	
		// Fill offset with random values
		crypto.getRandomValues(privateKey);
		
	} while(Secp256k1Zkp.isValidSecretKey(privateKey) !== true);
	
	// Log private key
	console.log("Using private key: " + Common.toHexString(privateKey));
	
	// Check address type
	switch(addressType) {
	
		// MQS address type
		case MQS_ADDRESS_TYPE:
		
			// Log message
			console.log("Using encryption type: MQS");
		
			{
				// Get MQS public key from the private key
				const publicKey = Secp256k1Zkp.publicKeyFromSecretKey(privateKey);
				
				// Get address from the MQS public key
				var address = Mqs.publicKeyToMqsAddress(publicKey, Consensus.getNetworkType() === Consensus.MAINNET_NETWORK_TYPE) + "@" + DOMAIN + ":" + PORT.toFixed();
			}
			
			// Break
			break;
		
		// Tor address type
		case TOR_ADDRESS_TYPE:
		
			// Log message
			console.log("Using encryption type: Tor");
			
			{
				// Get Tor private key from the random private key
				var otherTorPrivateKey = await Crypto.addressKey(Common.mergeArrays([privateKey, crypto.getRandomValues(new Uint8Array(Crypto.CHAIN_CODE_LENGTH))]), INDEX.toNumber());
				
				// Get Tor public key from the Tor private key
				const publicKey = Ed25519.publicKeyFromSecretKey(otherTorPrivateKey);
				
				// Get address from the public key
				var address = Tor.publicKeyToTorAddress(publicKey);
			}
			
			// Break
			break;
	}
	
	// Start encrypting slate on the hardware wallet
	let response = await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_START_ENCRYPTING_SLATE_MESSAGE_TYPE, {
				
		// Coin type
		"Coin Type": Consensus.getWalletType(),
		
		// Network type
		"Network Type": Consensus.getNetworkType(),
		
		// Account
		"Account": ACCOUNT,
		
		// Index
		"Index": INDEX,
		
		// Recipient address
		"Recipient Address": (new TextEncoder()).encode(address)
	
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_ENCRYPTED_SLATE_NONCE_AND_SALT_MESSAGE_TYPE);
	
	// Get nonce from response
	const nonce = response["Nonce"].at(-1);
	
	// Log nonce
	console.log("Using nonce: " + Common.toHexString(nonce));
	
	// Get salt from response
	const salt = ("Salt" in response === true) ? response["Salt"].at(-1) : new Uint8Array([]);
	
	// Check address type
	switch(addressType) {
	
		// MQS address type
		case MQS_ADDRESS_TYPE:
	
			// Log salt
			console.log("Using salt: " + Common.toHexString(salt));
			
			// Log domain
			console.log("Using domain: " + DOMAIN);
			
			// Log port
			console.log("Using port: " + PORT.toFixed());
			
			// Break
			break;
	}
	
	// Go through all chunks of the data
	let encryptedData = new Uint8Array([]);
	for(let i = 0; i < Math.ceil(DATA["length"] / MAXIMUM_CHUNK_SIZE); ++i) {
	
		// Continue encrypting slate on the hardware wallet
		const encryptedDataChunk = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_CONTINUE_ENCRYPTING_SLATE_MESSAGE_TYPE, {
				
			// Data
			"Data": DATA.subarray(i * MAXIMUM_CHUNK_SIZE, i * MAXIMUM_CHUNK_SIZE + MAXIMUM_CHUNK_SIZE)
		
		}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_ENCRYPTED_SLATE_DATA_MESSAGE_TYPE))["Encrypted Data"].at(-1);
		
		// Append encrypted data to list
		encryptedData = Common.mergeArrays([encryptedData, encryptedDataChunk]);
	}
	
	// Finish encrypting slate on the hardware wallet
	response = await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_FINISH_ENCRYPTING_SLATE_MESSAGE_TYPE, {}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_ENCRYPTED_SLATE_TAG_AND_SIGNATURE_MESSAGE_TYPE);
	
	// Check if using MQS encryption type
	if(addressType === MQS_ADDRESS_TYPE) {
	
		// Get tag from response
		const tag = response["Tag"].at(-1);
	
		// Get message signature from response
		const messageSignature = response["MQS Message Signature"].at(-1);
		
		// Append tag to encrypted data
		encryptedData = Common.mergeArrays([encryptedData, tag]);
		
		// Create message
		const message = JSON.stringify({
			"destination": {
				"public_key": address.split("@")[0],
				"domain": DOMAIN,
				"port": PORT
			},
			"nonce": Common.toHexString(nonce),
			"salt": Common.toHexString(salt),
			"encrypted_message": Common.toHexString(encryptedData)	
		});
		
		// Get message hash
		const messageHash = new Uint8Array(sha256.arrayBuffer(message));
		
		// Get MQS private key from the extended private key
		const mqsPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
		
		// Set expected message signature as the message hash signed by the MQS private key
		const expectedMessageSignature = Secp256k1Zkp.createMessageHashSignature(messageHash, mqsPrivateKey);
		
		// Log message signature
		console.log("Message signature: " + Common.toHexString(messageSignature));
	
		// Check if message signature is invalid
		if(Common.arraysAreEqual(messageSignature, expectedMessageSignature) === false) {
		
			// Log message
			console.log("Invalid message signature");
			
			// Throw error
			throw "Failed running encrypt slate test";
		}
	}
	
	// Otherwise
	else {
	
		// Get tag from response
		const tag = response["Tag"].at(-1);
	
		// Append tag to encrypted data
		encryptedData = Common.mergeArrays([encryptedData, tag]);
	}
	
	// Log encrypted slate
	console.log("Encrypted slate: " + Common.toHexString(encryptedData));
	
	// Check address type
	switch(addressType) {
	
		// MQS address type
		case MQS_ADDRESS_TYPE:
		
			// Get MQS private key from the extended private key
			const mqsPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get MQS public key from the MQS private key
			const mqsPublicKey = Secp256k1Zkp.publicKeyFromSecretKey(mqsPrivateKey);
			
			// Decrypt the encrypted data
			var decryptedData = await Mqs.decrypt(privateKey, mqsPublicKey, encryptedData, salt, nonce);
		
			// Break
			break;
		
		// Tor address type
		case TOR_ADDRESS_TYPE:
	
			// Get Tor private key from the extended private key
			const torPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get Tor public key from the Tor private key
			const torPublicKey = Ed25519.publicKeyFromSecretKey(torPrivateKey);
			
			// Decrypt the encrypted data
			var decryptedData = await Slatepack.decrypt(otherTorPrivateKey, torPublicKey, encryptedData, nonce);
			
			// Break
			break;
	}
	
	// Log decrypted slate
	console.log("Decrypted slate: " + Common.toHexString(decryptedData));
	
	// Check if decrypted data is invalid
	if(Common.arraysAreEqual(decryptedData, DATA) === false) {
	
		// Log message
		console.log("Invalid decrypted slate");
		
		// Throw error
		throw "Failed running encrypt slate test";
	}
	
	// Log message
	console.log("Passed running encrypt slate test");
}

// Decrypt slate test
async function decryptSlateTest(hardwareWallet, extendedPrivateKey, addressType) {

	// Log message
	console.log("Running decrypt slate test");
	
	// Data
	const DATA = crypto.getRandomValues(new Uint8Array(Math.round(Math.random() * Common.BYTE_MAX_VALUE + 1)));
	
	// Maximum chunk size
	const MAXIMUM_CHUNK_SIZE = 64;
	
	// AES IV size
	const AES_IV_SIZE = 16;
	
	// Log data
	console.log("Using data: " + Common.toHexString(DATA));
	
	// While random private key isn't a valid secret key
	const privateKey = new Uint8Array(Crypto.SECP256K1_SECRET_KEY_LENGTH);
	do {
	
		// Fill offset with random values
		crypto.getRandomValues(privateKey);
		
	} while(Secp256k1Zkp.isValidSecretKey(privateKey) !== true);
	
	// Log private key
	console.log("Using private key: " + Common.toHexString(privateKey));
	
	// Check address type
	switch(addressType) {
	
		// MQS address type
		case MQS_ADDRESS_TYPE:
		
			// Log message
			console.log("Using decryption type: MQS");
		
			{
				// Get public key from the private key
				const publicKey = Secp256k1Zkp.publicKeyFromSecretKey(privateKey);
				
				// Get address from the public key
				var address = Mqs.publicKeyToMqsAddress(publicKey, Consensus.getNetworkType() === Consensus.MAINNET_NETWORK_TYPE);
				
				// Get MQS private key from the extended private key
				const mqsPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
				
				// Get MQS public key from the MQS private key
				const mqsPublicKey = Secp256k1Zkp.publicKeyFromSecretKey(mqsPrivateKey);
				
				// Encrypt the data
				const encryptedData = await Mqs.encrypt(privateKey, mqsPublicKey, DATA);
				
				// Get salt from encrypted data
				var salt = encryptedData[Mqs.ENCRYPTED_DATA_SALT_INDEX];
				
				// Log salt
				console.log("Using salt: " + Common.toHexString(salt));
				
				// Set ephemeral X25519 public key to nothing
				var ephemeralX25519PublicKey = new Uint8Array([]);
				
				// Set encrypted file key to nothing
				var encryptedFileKey = new Uint8Array([]);
				
				// Set payload nonce to nothing
				var payloadNonce = new Uint8Array([]);
				
				// Get nonce from encrypted data
				var nonce = encryptedData[Mqs.ENCRYPTED_DATA_NONCE_INDEX];
				
				// Log nonce
				console.log("Using nonce: " + Common.toHexString(nonce));
				
				// Get encrypted message from encrypted data
				var encryptedMessage = encryptedData[Mqs.ENCRYPTED_DATA_DATA_INDEX];
			}
		
			// Break
			break;
		
		// Tor address type
		case TOR_ADDRESS_TYPE:
		
			// Log message
			console.log("Using decryption type: Tor");
		
			{
				// Get Tor private key from the random private key
				const otherTorPrivateKey = await Crypto.addressKey(Common.mergeArrays([privateKey, crypto.getRandomValues(new Uint8Array(Crypto.CHAIN_CODE_LENGTH))]), INDEX.toNumber());
				
				const publicKey = Ed25519.publicKeyFromSecretKey(otherTorPrivateKey);
				
				// Get address from the public key
				var address = Tor.publicKeyToTorAddress(publicKey);
				
				// Get Tor private key from the extended private key
				const torPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
				
				// Get Tor public key from the Tor private key
				const torPublicKey = Ed25519.publicKeyFromSecretKey(torPrivateKey);
				
				// Encrypt the data
				const encryptedData = await Slatepack.encrypt(otherTorPrivateKey, torPublicKey, DATA);
				
				// Set salt to nothing
				var salt = new Uint8Array([]);
				
				// Set ephemeral X25519 public key to nothing
				var ephemeralX25519PublicKey = new Uint8Array([]);
				
				// Set encrypted file key to nothing
				var encryptedFileKey = new Uint8Array([]);
				
				// Set payload nonce to nothing
				var payloadNonce = new Uint8Array([]);
				
				// Get nonce from encrypted data
				var nonce = encryptedData[Slatepack.ENCRYPTED_DATA_NONCE_INDEX];
				
				// Log nonce
				console.log("Using nonce: " + Common.toHexString(nonce));
				
				// Get encrypted message from encrypted data
				var encryptedMessage = encryptedData[Slatepack.ENCRYPTED_DATA_DATA_INDEX];
			}
			
			// Break
			break;
		
		// Slatepack address type
		case SLATEPACK_ADDRESS_TYPE:
		
			// Log message
			console.log("Using decryption type: Slatepack");
		
			{
				// Get Slatepack private key from the extended private key
				const slatepackPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
				
				// Get Slatepack public key from the Slatepack private key
				const slatepackPublicKey = Ed25519.publicKeyFromSecretKey(slatepackPrivateKey);
				
				// Encrypt the data
				const encryptedData = await Age.encrypt(slatepackPublicKey, DATA);
				
				// Set address to nothing
				var address = "";
				
				// Set salt to nothing
				var salt = new Uint8Array([]);
				
				// Get ephemeral X25519 public key from encrypted data
				var ephemeralX25519PublicKey = encryptedData[Age.ENCRYPTED_DATA_EPHEMERAL_X25519_PUBLIC_KEY_INDEX];
				
				// Log ephemeral X25519 public key
				console.log("Using ephemeral X25519 public key: " + Common.toHexString(ephemeralX25519PublicKey));
				
				// Get encrypted file key from encrypted data
				var encryptedFileKey = encryptedData[Age.ENCRYPTED_DATA_ENCRYPTED_FILE_KEY_INDEX];
				
				// Log encrypted file key
				console.log("Using encrypted file key: " + Common.toHexString(encryptedFileKey));
				
				// Get payload nonce from encrypted data
				var payloadNonce = encryptedData[Age.ENCRYPTED_DATA_PAYLOAD_NONCE_INDEX];
				
				// Log payload nonce
				console.log("Using payload nonce: " + Common.toHexString(payloadNonce));
				
				// Get nonce from encrypted data
				var nonce = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
				
				// Log nonce
				console.log("Using nonce: " + Common.toHexString(nonce));
				
				// Get encrypted message from encrypted data
				var encryptedMessage = encryptedData[Age.ENCRYPTED_DATA_DATA_INDEX];
			}
			
			// Break
			break;
	}
	
	// Log encrypted slate
	console.log("Encrypted slate: " + Common.toHexString(encryptedMessage));
	
	// Remove tag from the encrypted message
	const tag = encryptedMessage.subarray(encryptedMessage["length"] - Slatepack.TAG_LENGTH);
	encryptedMessage = encryptedMessage.subarray(0, encryptedMessage["length"] - Slatepack.TAG_LENGTH);
	
	// Start decrypting slate on the hardware wallet
	await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_START_DECRYPTING_SLATE_MESSAGE_TYPE, {
				
		// Coin type
		"Coin Type": Consensus.getWalletType(),
		
		// Network type
		"Network Type": Consensus.getNetworkType(),
		
		// Account
		"Account": ACCOUNT,
		
		// Index
		"Index": INDEX,
		
		// Nonce
		"Nonce": nonce,
		
		// Sender address or ephemeral X25519 public key
		"Sender Address Or Ephemeral X25519 Public Key": Common.mergeArrays([(new TextEncoder()).encode(address), ephemeralX25519PublicKey]),
		
		// Salt or encrypted file key
		"Salt Or Encrypted File Key": Common.mergeArrays([salt, encryptedFileKey]),
		
		// Payload nonce
		"Payload Nonce": payloadNonce
		
	}, HardwareWalletDefinitions.TREZOR_SUCCESS_MESSAGE_TYPE);
	
	// Go through all chunks of the encrypted message
	const decryptedDataChunks = [];
	for(let i = 0; i < Math.ceil(encryptedMessage["length"] / MAXIMUM_CHUNK_SIZE); ++i) {
	
		// Continue decrypting slate on the hardware wallet
		const decryptedDataChunk = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_CONTINUE_DECRYPTING_SLATE_MESSAGE_TYPE, {
				
			// Encrypted data
			"Encrypted Data": encryptedMessage.subarray(i * MAXIMUM_CHUNK_SIZE, i * MAXIMUM_CHUNK_SIZE + MAXIMUM_CHUNK_SIZE)
		
		}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_DECRYPTED_SLATE_DATA_MESSAGE_TYPE))["Data"].at(-1);
		
		// Append decrypted data chunk to list
		decryptedDataChunks.push(decryptedDataChunk);
	}
	
	// Finish decrypting slate on the hardware wallet
	const aesKey = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_FINISH_DECRYPTING_SLATE_MESSAGE_TYPE, {
				
		// Tag
		"Tag": tag
	
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_DECRYPTED_SLATE_AES_KEY_MESSAGE_TYPE))["AES Key"].at(-1);
	
	// Log AES key
	console.log("Using AES key: " + Common.toHexString(aesKey));
	
	// Create crypto key from AES key
	const cryptoKey = await crypto["subtle"].importKey("raw", aesKey, {"name": "AES-CBC"}, false, ["decrypt"]);
	
	// Go through all decrypted data chunks
	let decryptedData = new Uint8Array([]);
	for(let i = 0; i < decryptedDataChunks["length"]; ++i) {
	
		// Decrypt the data chunk with the crypto key
		const data = new Uint8Array(await crypto["subtle"].decrypt({"name": "AES-CBC", "iv": new Uint8Array(AES_IV_SIZE)}, cryptoKey, decryptedDataChunks[i]));
		
		// Append decrypted data chunk to list
		decryptedData = Common.mergeArrays([decryptedData, data]);
	}
	
	// Log decrypted slate
	console.log("Decrypted slate: " + Common.toHexString(decryptedData));
	
	// Check if decrypted data is invalid
	if(Common.arraysAreEqual(decryptedData, DATA) === false) {
	
		// Log message
		console.log("Invalid decrypted slate");
		
		// Throw error
		throw "Failed running decrypt slate test";
	}
	
	// Log message
	console.log("Passed running decrypt slate test");
}

// Receive transaction test
async function receiveTransactionTest(hardwareWallet, extendedPrivateKey, switchType, features, lockHeight, relativeHeight, senderAddressType, paymentProofType) {

	// Log message
	console.log("Running receive transaction test");

	// Output
	const OUTPUT = new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER));
	
	// Input
	const INPUT = new BigNumber(0);
	
	// Fee
	const FEE = new BigNumber((features === SlateKernel.COINBASE_FEATURES) ? 0 : (Math.floor(Math.random() * (((Slate.MAXIMUM_FEE === Number.POSITIVE_INFINITY) ? Number.MAX_SAFE_INTEGER : Slate.MAXIMUM_FEE) - Slate.MINIMUM_FEE + 1)) + Slate.MINIMUM_FEE));
	
	// Identifier
	const IDENTIFIER = new Identifier(Common.toHexString(Common.mergeArrays([new Uint8Array([Math.round(Math.random() * Identifier.MAX_DEPTH)]), crypto.getRandomValues(new Uint8Array(Identifier.MAX_DEPTH * Uint32Array["BYTES_PER_ELEMENT"]))])));
	
	// Message
	const MESSAGE = "This is a message";
	
	// Log output
	console.log("Using output: " + OUTPUT.toFixed());
	
	// Log identifier
	console.log("Using identifier: " + Common.toHexString(IDENTIFIER.getValue()));
	
	// Log message
	console.log("Using message: " + MESSAGE);
	
	// Check switch type
	switch(switchType) {
	
		// Switch type none
		case Crypto.SWITCH_TYPE_NONE:
		
			// Log switch type
			console.log("Using switch type: none");
		
			// Break
			break;
		
		// Regular switch type
		case Crypto.SWITCH_TYPE_REGULAR:
		
			// Log switch type
			console.log("Using switch type: regular");
		
			// Break
			break;
	}
	
	// Check features
	switch(features) {
	
		// Coinbase features
		case SlateKernel.COINBASE_FEATURES:
		
			// Log features
			console.log("Using features: coinbase");
		
			// Break
			break;
		
		// Plain features
		case SlateKernel.PLAIN_FEATURES:
		
			// Log features
			console.log("Using features: plain");
			
			// Log fee
			console.log("Using fee: " + FEE.toFixed());
		
			// Break
			break;
		
		// Height locked features
		case SlateKernel.HEIGHT_LOCKED_FEATURES:
		
			// Log features
			console.log("Using features: height locked");
			
			// Log fee
			console.log("Using fee: " + FEE.toFixed());
			
			// Log lock height
			console.log("Using lock height: " + lockHeight.toFixed());
		
			// Break
			break;
		
		// No recent duplicate features
		case SlateKernel.NO_RECENT_DUPLICATE_FEATURES:
		
			// Log features
			console.log("Using features: no recent duplicate");
			
			// Log fee
			console.log("Using fee: " + FEE.toFixed());
			
			// Log relative height
			console.log("Using relative height: " + relativeHeight.toFixed());
		
			// Break
			break;
	}
	
	// Check sender address type
	switch(senderAddressType) {
	
		// MQS address type
		case MQS_ADDRESS_TYPE:
		
			// Log sender address type
			console.log("Using sender address type: MQS");
			
			// Get MQS private key from the extended private key
			const mqsPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.plus(1).toNumber());
			
			// Get MQS public key from the MQS private key
			const mqsPublicKey = Secp256k1Zkp.publicKeyFromSecretKey(mqsPrivateKey);
			
			// Get sender address from the MQS public key
			var senderAddress = Mqs.publicKeyToMqsAddress(mqsPublicKey, Consensus.getNetworkType() === Consensus.MAINNET_NETWORK_TYPE);
		
			// Break
			break;
		
		// Tor address type
		case TOR_ADDRESS_TYPE:
		
			// Log sender address type
			console.log("Using sender address type: Tor");
			
			// Get Tor private key from the extended private key
			const torPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.plus(1).toNumber());
			
			// Get Tor public key from the Tor private key
			const torPublicKey = Ed25519.publicKeyFromSecretKey(torPrivateKey);
			
			// Get sender address from the Tor public key
			var senderAddress = Tor.publicKeyToTorAddress(torPublicKey);
		
			// Break
			break;
		
		// Slatepack address type
		case SLATEPACK_ADDRESS_TYPE:
		
			// Log sender address type
			console.log("Using sender address type: Slatepack");
			
			// Get Slatepack private key from the extended private key
			const slatepackPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.plus(1).toNumber());
			
			// Get Slatepack public key from the Slatepack private key
			const slatepackPublicKey = Ed25519.publicKeyFromSecretKey(slatepackPrivateKey);
			
			// Get sender address from the Slatepack public key
			var senderAddress = Slatepack.publicKeyToSlatepackAddress(slatepackPublicKey);
		
			// Break
			break;
	}
	
	// Get random kernel commitment
	const kernelCommit = await Crypto.commit(extendedPrivateKey, OUTPUT, IDENTIFIER, switchType);
	
	// Check payment proof type
	switch(paymentProofType) {
	
		// No payment proof type
		case NO_PAYMENT_PROOF_TYPE:
		
			// Log payment proof type
			console.log("Using payment proof type: none");
			
			// Set receiver address type
			var receiverAddressType = senderAddressType;
		
			// Break
			break;
		
		// MQS payment proof type
		case MQS_PAYMENT_PROOF_TYPE:
		
			// Log payment proof type
			console.log("Using payment proof type: MQS");
			
			// Set receiver address type
			var receiverAddressType = MQS_ADDRESS_TYPE;
		
			// Get MQS private key from the extended private key
			const mqsPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Set payment proof message
			var paymentProofMessage = Slate.getPaymentProofMessage(OUTPUT, kernelCommit, senderAddress);
			
			// Get payment proof message hash
			const paymentProofMessageHash = new Uint8Array(sha256.arrayBuffer(paymentProofMessage));
			
			// Set expected payment proof as the payment proof message hash signed by the MQS private key
			var expectedPaymentProof = Secp256k1Zkp.createMessageHashSignature(paymentProofMessageHash, mqsPrivateKey);
			
			// Break
			break;
		
		// Tor payment proof type
		case TOR_PAYMENT_PROOF_TYPE:
		
			// Log payment proof type
			console.log("Using payment proof type: Tor");
			
			// Set receiver address type
			var receiverAddressType = TOR_ADDRESS_TYPE;
		
			// Get Tor private key from the extended private key
			const torPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Set payment proof message
			var paymentProofMessage = Slate.getPaymentProofMessage(OUTPUT, kernelCommit, senderAddress);
			
			// Set expected payment proof as the payment proof message signed by the Tor private key
			var expectedPaymentProof = Ed25519.sign(paymentProofMessage, torPrivateKey);
		
			// Break
			break;
		
		// Slatepack payment proof type
		case SLATEPACK_PAYMENT_PROOF_TYPE:
		
			// Log payment proof type
			console.log("Using payment proof type: Slatepack");
			
			// Set receiver address type
			var receiverAddressType = SLATEPACK_ADDRESS_TYPE;
		
			// Get Slatepack private key from the extended private key
			const slatepackPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Set payment proof message
			var paymentProofMessage = Slate.getPaymentProofMessage(OUTPUT, kernelCommit, senderAddress);
			
			// Set expected payment proof as the payment proof message signed by the Slatepack private key
			var expectedPaymentProof = Ed25519.sign(paymentProofMessage, slatepackPrivateKey);
		
			// Break
			break;
	}
	
	// Get the output's blinding factor
	const outputBlindingFactor = await Crypto.deriveSecretKey(extendedPrivateKey, OUTPUT, IDENTIFIER, switchType);
	
	// Get the sum of all the transaction's blinding factors
	const transactionBlindingFactor = Secp256k1Zkp.blindSum([outputBlindingFactor], []);
	
	// Get the expected transaction public key from the transaction's blinding factor
	const expectedTransactionPublicKey = Secp256k1Zkp.publicKeyFromSecretKey(transactionBlindingFactor);

	// Start transaction on the hardware wallet
	await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_START_TRANSACTION_MESSAGE_TYPE, {
				
		// Coin type
		"Coin Type": Consensus.getWalletType(),
		
		// Network type
		"Network Type": Consensus.getNetworkType(),
		
		// Account
		"Account": ACCOUNT,
		
		// Index
		"Index": INDEX,
		
		// Output
		"Output": OUTPUT,
		
		// Input
		"Input": INPUT,
		
		// Fee
		"Fee": FEE,
		
		// Secret nonce index
		"Secret Nonce Index": 0,
		
		// Address
		"Address": (paymentProofType !== NO_PAYMENT_PROOF_TYPE) ? (new TextEncoder()).encode(senderAddress) : new Uint8Array([])
		
	}, HardwareWalletDefinitions.TREZOR_SUCCESS_MESSAGE_TYPE);
	
	// Include output in the transaction on the hardware wallet
	await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_CONTINUE_TRANSACTION_INCLUDE_OUTPUT_MESSAGE_TYPE, {
				
		// Identifier
		"Identifier": IDENTIFIER.getValue(),
		
		// Value
		"Value": OUTPUT,
		
		// Switch type
		"Switch Type": switchType
		
	}, HardwareWalletDefinitions.TREZOR_SUCCESS_MESSAGE_TYPE);
	
	// Get the transaction public key from the hardware wallet
	const transactionPublicKey = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_CONTINUE_TRANSACTION_GET_PUBLIC_KEY_MESSAGE_TYPE, {}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_TRANSACTION_PUBLIC_KEY_MESSAGE_TYPE))["Public Key"].at(-1);

	// Log transaction public key
	console.log("Transaction public key: " + Common.toHexString(transactionPublicKey));
	
	// Check if transaction public key is invalid
	if(Common.arraysAreEqual(transactionPublicKey, expectedTransactionPublicKey) === false) {
	
		// Log message
		console.log("Invalid transaction public key");
		
		// Throw error
		throw "Failed running receive transaction test";
	}
	
	// Get the transaction public nonce from the hardware wallet
	const publicNonce = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_CONTINUE_TRANSACTION_GET_PUBLIC_NONCE_MESSAGE_TYPE, {}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_TRANSACTION_PUBLIC_NONCE_MESSAGE_TYPE))["Public Nonce"].at(-1);

	// Log transaction public nonce
	console.log("Transaction public nonce: " + Common.toHexString(publicNonce));
	
	// Get the message signature from the hardware wallet
	const messageSignature = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_CONTINUE_TRANSACTION_GET_MESSAGE_SIGNATURE_MESSAGE_TYPE, {
	
		// Message
		"Message": (new TextEncoder()).encode(MESSAGE)
		
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_TRANSACTION_MESSAGE_SIGNATURE_MESSAGE_TYPE))["Message Signature"].at(-1);

	// Log message signature
	console.log("Message signature: " + Common.toHexString(messageSignature));
	
	// Check if features is coinbase
	if(features === SlateKernel.COINBASE_FEATURES) {
		
		// Get excess from commit and over commit
		const excess = Secp256k1Zkp.pedersenCommitSum([
		
			// Commit
			await Crypto.commit(extendedPrivateKey, OUTPUT, IDENTIFIER, switchType)
		], [
		
			// Over commit
			Crypto.commitAmount(OUTPUT)
		]);
		
		// Get public key from excess
		var publicKey = Secp256k1Zkp.pedersenCommitToPublicKey(excess);
	}
	
	// Otherwise
	else {
	
		// Get public key from transaction public key
		var publicKey = expectedTransactionPublicKey;
	}
	
	// Check if message signature is invalid
	if(Secp256k1Zkp.verifySingleSignerSignature(messageSignature, Blake2b.compute(Crypto.SINGLE_SIGNER_MESSAGE_LENGTH, (new TextEncoder()).encode(MESSAGE), new Uint8Array([])), Secp256k1Zkp.NO_PUBLIC_NONCE, publicKey, publicKey, false) !== true) {
	
		// Log message
		console.log("Invalid message signature");
		
		// Throw error
		throw "Failed running receive transaction test";
	}
	
	// Log message
	console.log("Verify that the account index on the device is: " + ACCOUNT.toFixed());
	
	// Check features
	switch(features) {
	
		// Plain features
		case SlateKernel.PLAIN_FEATURES:
		
			// Set kernel information to features
			var kernelInformation = new Uint8Array([features]);
		
			// Log message
			console.log("Verify that the transaction's kernel features on the device is: Plain");
			
			// Break
			break;
	
		// Coinbase features
		case SlateKernel.COINBASE_FEATURES:
		
			// Set kernel information to features
			var kernelInformation = new Uint8Array([features]);
			
			// Log message
			console.log("Verify that the transaction's kernel features on the device is: Coinbase");
		
			// Break
			break;
		
		// Height locked features
		case SlateKernel.HEIGHT_LOCKED_FEATURES:
		
			// Set kernel information to features followed by the lock height
			var kernelInformation = Common.mergeArrays([
			
				// Features
				new Uint8Array([features]),
				
				// Lock height
				new Uint8Array(lockHeight.toBytes(BigNumber.LITTLE_ENDIAN, Common.BYTES_IN_A_UINT64))
			]);
			
			// Log message
			console.log("Verify that the transaction's kernel features on the device is: Height Locked");
			
			// Log message
			console.log("Verify that the transaction's lock height on the device is: " + lockHeight.toFixed());
		
			// Break
			break;
		
		// No recent duplicate features
		case SlateKernel.NO_RECENT_DUPLICATE_FEATURES:
		
			// Set kernel features to features followed by the relative height
			var kernelInformation = Common.mergeArrays([
			
				// Features
				new Uint8Array([features]),
				
				// Relative height
				new Uint8Array(relativeHeight.toBytes(BigNumber.LITTLE_ENDIAN, Common.BYTES_IN_A_UINT16))
			]);
			
			// Log message
			console.log("Verify that the transaction's kernel features on the device is: No Recent Duplicate");
			
			// Log message
			console.log("Verify that the transaction's relative height on the device is: " + relativeHeight.toFixed());
		
			// Break
			break;
	}
	
	// Log message
	console.log("Verify that the transaction's amount on the device is: " + OUTPUT.dividedBy(Consensus.VALUE_NUMBER_BASE).toFixed());
	
	// Log message
	console.log("Verify that the transaction's fee on the device is: " + FEE.dividedBy(Consensus.VALUE_NUMBER_BASE).toFixed());

	
	// Check if using a payment proof
	if(paymentProofType !== NO_PAYMENT_PROOF_TYPE) {
	
		// Log message
		console.log("Verify that the transaction's sender payment proof address on the device is: " + senderAddress);
	}
	
	// Otherwise
	else {
	
		// Log message
		console.log("Verify that the transaction contains no payment proof on the device");
	}
	
	// Get signature for the transaction from the hardware wallet
	const response = await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_FINISH_TRANSACTION_MESSAGE_TYPE, {
	
		// Address type
		"Parameter One": receiverAddressType,
		
		// Public nonce
		"Public Nonce": publicNonce,
		
		// Public key
		"Public Key": publicKey,
		
		// Kernel information
		"Kernel Information": kernelInformation,
		
		// Kernel commitment
		"Kernel Commitment": (paymentProofType !== NO_PAYMENT_PROOF_TYPE) ? kernelCommit : new Uint8Array([])
		
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_TRANSACTION_SIGNATURE_AND_PAYMENT_PROOF_MESSAGE_TYPE);
	
	// Get signature from response
	const signature = response["Signature"].at(-1);
	
	// Log transaction signature
	console.log("Transaction signature: " + Common.toHexString(signature));
	
	// Check if signature is invalid
	if(Secp256k1Zkp.verifySingleSignerSignature(signature, SlateKernel.signatureMessage(features, FEE, lockHeight, relativeHeight), publicNonce, publicKey, publicKey, true) !== true) {
	
		// Log message
		console.log("Invalid transaction signature");
		
		// Throw error
		throw "Failed running receive transaction test";
	}
	
	// Check if using a payment proof
	if(paymentProofType !== NO_PAYMENT_PROOF_TYPE) {
	
		// Get payment proof from response
		const paymentProof = response["Payment Proof"].at(-1);
		
		// Log transaction payment proof
		console.log("Transaction payment proof: " + Common.toHexString(paymentProof));
		
		// Check if payment proof is invalid
		if(Common.arraysAreEqual(paymentProof, expectedPaymentProof) === false) {
		
			// Log message
			console.log("Invalid payment proof");
			
			// Throw error
			throw "Failed running receive transaction test";
		}
	}
	
	// Log message
	console.log("Passed running receive transaction test");
}

// Send transaction test
async function sendTransactionTest(hardwareWallet, extendedPrivateKey, switchType, features, lockHeight, relativeHeight, senderAddressType, paymentProofType) {

	// Log message
	console.log("Running send transaction test");

	// Output
	const OUTPUT = new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER));
	
	// Fee
	const FEE = new BigNumber(Math.floor(Math.random() * (((Slate.MAXIMUM_FEE === Number.POSITIVE_INFINITY) ? Number.MAX_SAFE_INTEGER : Slate.MAXIMUM_FEE) - Slate.MINIMUM_FEE + 1)) + Slate.MINIMUM_FEE);
	
	// Input
	const INPUT = (new BigNumber(Math.round(Math.random() * Number.MAX_SAFE_INTEGER))).plus(OUTPUT);
	
	// Output identifier
	const OUTPUT_IDENTIFIER = new Identifier(Common.toHexString(Common.mergeArrays([new Uint8Array([Math.round(Math.random() * Identifier.MAX_DEPTH)]), crypto.getRandomValues(new Uint8Array(Identifier.MAX_DEPTH * Uint32Array["BYTES_PER_ELEMENT"]))])));
	
	// Input identifier
	const INPUT_IDENTIFIER = new Identifier(Common.toHexString(Common.mergeArrays([new Uint8Array([Math.round(Math.random() * Identifier.MAX_DEPTH)]), crypto.getRandomValues(new Uint8Array(Identifier.MAX_DEPTH * Uint32Array["BYTES_PER_ELEMENT"]))])));
	
	// Input switch type
	const INPUT_SWITCH_TYPE = Crypto.SWITCH_TYPE_REGULAR;
	
	// Message
	const MESSAGE = "This is a message";
	
	// Log output
	console.log("Using output: " + OUTPUT.toFixed());
	
	// Log input
	console.log("Using input: " + INPUT.toFixed());
	
	// Log fee
	console.log("Using fee: " + FEE.toFixed());
	
	// Log output identifier
	console.log("Using output identifier: " + Common.toHexString(OUTPUT_IDENTIFIER.getValue()));
	
	// Log input identifier
	console.log("Using input identifier: " + Common.toHexString(INPUT_IDENTIFIER.getValue()));
	
	// Log message
	console.log("Using message: " + MESSAGE);
	
	// Check switch type
	switch(switchType) {
	
		// Switch type none
		case Crypto.SWITCH_TYPE_NONE:
		
			// Log switch type
			console.log("Using switch type: none");
		
			// Break
			break;
		
		// Regular switch type
		case Crypto.SWITCH_TYPE_REGULAR:
		
			// Log switch type
			console.log("Using switch type: regular");
		
			// Break
			break;
	}
	
	// Check features
	switch(features) {
	
		// Plain features
		case SlateKernel.PLAIN_FEATURES:
		
			// Log features
			console.log("Using features: plain");
		
			// Break
			break;
		
		// Height locked features
		case SlateKernel.HEIGHT_LOCKED_FEATURES:
		
			// Log features
			console.log("Using features: height locked");
			
			// Log lock height
			console.log("Using lock height: " + lockHeight.toFixed());
		
			// Break
			break;
		
		// No recent duplicate features
		case SlateKernel.NO_RECENT_DUPLICATE_FEATURES:
		
			// Log features
			console.log("Using features: no recent duplicate");
			
			// Log relative height
			console.log("Using relative height: " + relativeHeight.toFixed());
		
			// Break
			break;
	}
	
	// Check sender address type
	switch(senderAddressType) {
	
		// MQS address type
		case MQS_ADDRESS_TYPE:
		
			// Log sender address type
			console.log("Using sender address type: MQS");
			
			// Get MQS private key from the extended private key
			const mqsPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get MQS public key from the MQS private key
			const mqsPublicKey = Secp256k1Zkp.publicKeyFromSecretKey(mqsPrivateKey);
			
			// Get sender address from the MQS public key
			var senderAddress = Mqs.publicKeyToMqsAddress(mqsPublicKey, Consensus.getNetworkType() === Consensus.MAINNET_NETWORK_TYPE);
		
			// Break
			break;
		
		// Tor address type
		case TOR_ADDRESS_TYPE:
		
			// Log sender address type
			console.log("Using sender address type: Tor");
			
			// Get Tor private key from the extended private key
			const torPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get Tor public key from the Tor private key
			const torPublicKey = Ed25519.publicKeyFromSecretKey(torPrivateKey);
			
			// Get sender address from the Tor public key
			var senderAddress = Tor.publicKeyToTorAddress(torPublicKey);
		
			// Break
			break;
		
		// Slatepack address type
		case SLATEPACK_ADDRESS_TYPE:
		
			// Log sender address type
			console.log("Using sender address type: Slatepack");
			
			// Get Slatepack private key from the extended private key
			const slatepackPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get Slatepack public key from the Slatepack private key
			const slatepackPublicKey = Ed25519.publicKeyFromSecretKey(slatepackPrivateKey);
			
			// Get sender address from the Slatepack public key
			var senderAddress = Slatepack.publicKeyToSlatepackAddress(slatepackPublicKey);
		
			// Break
			break;
	}
	
	// Get random kernel commitment
	const kernelCommit = await Crypto.commit(extendedPrivateKey, INPUT.minus(OUTPUT), OUTPUT_IDENTIFIER, INPUT_SWITCH_TYPE);
	
	// Set payment proof message
	const paymentProofMessage = Slate.getPaymentProofMessage(INPUT.minus(OUTPUT), kernelCommit, senderAddress);
	
	// Check payment proof type
	switch(paymentProofType) {
	
		// No payment proof type
		case NO_PAYMENT_PROOF_TYPE:
		
			// Log payment proof type
			console.log("Using payment proof type: none");
		
			// Break
			break;
		
		// MQS payment proof type
		case MQS_PAYMENT_PROOF_TYPE:
		
			// Log payment proof type
			console.log("Using payment proof type: MQS");
		
			// Get MQS private key from the extended private key
			const mqsPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get MQS public key from the MQS private key
			const mqsPublicKey = Secp256k1Zkp.publicKeyFromSecretKey(mqsPrivateKey);
			
			// Get receiver address from the MQS public key
			var receiverAddress = Mqs.publicKeyToMqsAddress(mqsPublicKey, Consensus.getNetworkType() === Consensus.MAINNET_NETWORK_TYPE);
			
			// Get payment proof message hash
			const paymentProofMessageHash = new Uint8Array(sha256.arrayBuffer(paymentProofMessage));
			
			// Set payment proof as the payment proof message hash signed by the MQS private key
			var paymentProof = Secp256k1Zkp.createMessageHashSignature(paymentProofMessageHash, mqsPrivateKey);
			
			// Break
			break;
		
		// Tor payment proof type
		case TOR_PAYMENT_PROOF_TYPE:
		
			// Log payment proof type
			console.log("Using payment proof type: Tor");
		
			// Get Tor private key from the extended private key
			const torPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get Tor public key from the Tor private key
			const torPublicKey = Ed25519.publicKeyFromSecretKey(torPrivateKey);
			
			// Get receiver address from the Tor public key
			var receiverAddress = Tor.publicKeyToTorAddress(torPublicKey);
			
			// Set payment proof as the payment proof message signed by the Tor private key
			var paymentProof = Ed25519.sign(paymentProofMessage, torPrivateKey);
		
			// Break
			break;
		
		// Slatepack payment proof type
		case SLATEPACK_PAYMENT_PROOF_TYPE:
		
			// Log payment proof type
			console.log("Using payment proof type: Slatepack");
		
			// Get Slatepack private key from the extended private key
			const slatepackPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
			
			// Get Slatepack public key from the Slatepack private key
			const slatepackPublicKey = Ed25519.publicKeyFromSecretKey(slatepackPrivateKey);
			
			// Get receiver address from the Slatepack public key
			var receiverAddress = Slatepack.publicKeyToSlatepackAddress(slatepackPublicKey);
			
			// Set payment proof as the payment proof message signed by the Slatepack private key
			var paymentProof = Ed25519.sign(paymentProofMessage, slatepackPrivateKey);
		
			// Break
			break;
	}
	
	// While offset isn't a valid secret key
	const offset = new Uint8Array(Crypto.BLINDING_FACTOR_LENGTH);
	do {
	
		// Fill offset with random values
		crypto.getRandomValues(offset);
		
	} while(Secp256k1Zkp.isValidSecretKey(offset) !== true);
	
	// Log offset
	console.log("Using offset: " + Common.toHexString(offset));
	
	// Start transaction twice to test secret nonce index
	let secretNonceIndex = 0;
	for(let i = 0; i < 2; ++i) {
	
		// Start transaction on the hardware wallet
		await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_START_TRANSACTION_MESSAGE_TYPE, {
				
			// Coin type
			"Coin Type": Consensus.getWalletType(),
			
			// Network type
			"Network Type": Consensus.getNetworkType(),
			
			// Account
			"Account": ACCOUNT,
			
			// Index
			"Index": INDEX,
			
			// Output
			"Output": OUTPUT,
			
			// Input
			"Input": INPUT,
			
			// Fee
			"Fee": FEE,
			
			// Secret nonce index
			"Secret Nonce Index": secretNonceIndex,
			
			// Address
			"Address": (paymentProofType !== NO_PAYMENT_PROOF_TYPE) ? (new TextEncoder()).encode(receiverAddress) : new Uint8Array([])
			
		}, HardwareWalletDefinitions.TREZOR_SUCCESS_MESSAGE_TYPE);
		
		// Include output in the transaction on the hardware wallet
		await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_CONTINUE_TRANSACTION_INCLUDE_OUTPUT_MESSAGE_TYPE, {
				
			// Identifier
			"Identifier": OUTPUT_IDENTIFIER.getValue(),
			
			// Value
			"Value": OUTPUT,
			
			// Switch type
			"Switch Type": switchType
			
		}, HardwareWalletDefinitions.TREZOR_SUCCESS_MESSAGE_TYPE);
		
		// Include input in the transaction on the hardware wallet
		await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_CONTINUE_TRANSACTION_INCLUDE_INPUT_MESSAGE_TYPE, {
				
			// Identifier
			"Identifier": INPUT_IDENTIFIER.getValue(),
			
			// Value
			"Value": INPUT.plus(FEE),
			
			// Switch type
			"Switch Type": INPUT_SWITCH_TYPE
			
		}, HardwareWalletDefinitions.TREZOR_SUCCESS_MESSAGE_TYPE);
		
		// Apply offset to the transaction on the hardware wallet
		const response = await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_CONTINUE_TRANSACTION_APPLY_OFFSET_MESSAGE_TYPE, {
				
			// Offset
			"Offset": offset
			
		}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_TRANSACTION_SECRET_NONCE_INDEX_MESSAGE_TYPE);
		
		// Check if response contains a secret nonce index
		if("Secret Nonce Index" in response === true) {
		
			// Get secret nonce index from response
			secretNonceIndex = response["Secret Nonce Index"].at(-1);
			
			// Log secret nonce index
			console.log("Secret nonce index: " + secretNonceIndex);
		}
	}
	
	// Get the output's blinding factor
	const outputBlindingFactor = await Crypto.deriveSecretKey(extendedPrivateKey, OUTPUT, OUTPUT_IDENTIFIER, switchType);
	
	// Get the input's blinding factor
	const inputBlindingFactor = await Crypto.deriveSecretKey(extendedPrivateKey, INPUT.plus(FEE), INPUT_IDENTIFIER, INPUT_SWITCH_TYPE);
	
	// Get the sum of all the transaction's blinding factors
	let transactionBlindingFactor = Secp256k1Zkp.blindSum([outputBlindingFactor], [inputBlindingFactor]);
	
	// Update the transaction blinding factor to include the offset
	transactionBlindingFactor = Secp256k1Zkp.blindSum([transactionBlindingFactor], [offset]);
	
	// Get the expected transaction public key from the transaction's blinding factor
	const expectedTransactionPublicKey = Secp256k1Zkp.publicKeyFromSecretKey(transactionBlindingFactor);
	
	// Get the transaction public key from the hardware wallet
	const publicKey = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_CONTINUE_TRANSACTION_GET_PUBLIC_KEY_MESSAGE_TYPE, {}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_TRANSACTION_PUBLIC_KEY_MESSAGE_TYPE))["Public Key"].at(-1);
	
	// Log transaction public key after offset
	console.log("Transaction public key after offset: " + Common.toHexString(publicKey));
	
	// Check if transaction public key is invalid
	if(Common.arraysAreEqual(publicKey, expectedTransactionPublicKey) === false) {
	
		// Log message
		console.log("Invalid transaction public key");
		
		// Throw error
		throw "Failed running send transaction test";
	}
	
	// Get the transaction public nonce from the hardware wallet
	const publicNonce = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_CONTINUE_TRANSACTION_GET_PUBLIC_NONCE_MESSAGE_TYPE, {}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_TRANSACTION_PUBLIC_NONCE_MESSAGE_TYPE))["Public Nonce"].at(-1);
	
	// Log transaction public nonce
	console.log("Transaction public nonce: " + Common.toHexString(publicNonce));
	
	// Get the message signature from the hardware wallet
	const messageSignature = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_CONTINUE_TRANSACTION_GET_MESSAGE_SIGNATURE_MESSAGE_TYPE, {
	
		// Message
		"Message": (new TextEncoder()).encode(MESSAGE)
		
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_TRANSACTION_MESSAGE_SIGNATURE_MESSAGE_TYPE))["Message Signature"].at(-1);
	
	// Log message signature
	console.log("Message signature: " + Common.toHexString(messageSignature));
	
	// Check if message signature is invalid
	if(Secp256k1Zkp.verifySingleSignerSignature(messageSignature, Blake2b.compute(Crypto.SINGLE_SIGNER_MESSAGE_LENGTH, (new TextEncoder()).encode(MESSAGE), new Uint8Array([])), Secp256k1Zkp.NO_PUBLIC_NONCE, publicKey, publicKey, false) !== true) {
	
		// Log message
		console.log("Invalid message signature");
		
		// Throw error
		throw "Failed running send transaction test";
	}
	
	// Log message
	console.log("Verify that the account index on the device is: " + ACCOUNT.toFixed());
	
	// Check features
	switch(features) {
	
		// Plain features
		case SlateKernel.PLAIN_FEATURES:
		
			// Set kernel information to features
			var kernelInformation = new Uint8Array([features]);
			
			// Log message
			console.log("Verify that the transaction's kernel features on the device is: Plain");
			
			// Break
			break;
		
		// Height locked features
		case SlateKernel.HEIGHT_LOCKED_FEATURES:
		
			// Set kernel information to features followed by the lock height
			var kernelInformation = Common.mergeArrays([
			
				// Features
				new Uint8Array([features]),
				
				// Lock height
				new Uint8Array(lockHeight.toBytes(BigNumber.LITTLE_ENDIAN, Common.BYTES_IN_A_UINT64))
			]);
			
			// Log message
			console.log("Verify that the transaction's kernel features on the device is: Height Locked");
			
			// Log message
			console.log("Verify that the transaction's lock height on the device is: " + lockHeight.toFixed());
			
			// Break
			break;
		
		// No recent duplicate features
		case SlateKernel.NO_RECENT_DUPLICATE_FEATURES:
		
			// Set kernel features to features followed by the relative height
			var kernelInformation = Common.mergeArrays([
			
				// Features
				new Uint8Array([features]),
				
				// Relative height
				new Uint8Array(relativeHeight.toBytes(BigNumber.LITTLE_ENDIAN, Common.BYTES_IN_A_UINT16))
			]);
			
			// Log message
			console.log("Verify that the transaction's kernel features on the device is: No Recent Duplicate");
			
			// Log message
			console.log("Verify that the transaction's relative height on the device is: " + relativeHeight.toFixed());
			
			// Break
			break;
	}
	
	// Log message
	console.log("Verify that the transaction's amount on the device is: " + INPUT.minus(OUTPUT).dividedBy(Consensus.VALUE_NUMBER_BASE).toFixed());
	
	// Log message
	console.log("Verify that the transaction's fee on the device is: " + FEE.dividedBy(Consensus.VALUE_NUMBER_BASE).toFixed());
	
	// Check if using a payment proof
	if(paymentProofType !== NO_PAYMENT_PROOF_TYPE) {
		
		// Log message
		console.log("Verify that the transaction's recipient payment proof address on the device is: " + receiverAddress);
	}
	
	// Otherwise
	else {
	
		// Log message
		console.log("Verify that the transaction contains no payment proof on the device");
	}
	
	// Get signature for the transaction from the hardware wallet
	const signature = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_FINISH_TRANSACTION_MESSAGE_TYPE, {
	
		// Address type
		"Parameter One": senderAddressType,
		
		// Public nonce
		"Public Nonce": publicNonce,
		
		// Public key
		"Public Key": publicKey,
		
		// Kernel information
		"Kernel Information": kernelInformation,
		
		// Kernel commitment
		"Kernel Commitment": (paymentProofType !== NO_PAYMENT_PROOF_TYPE) ? kernelCommit : new Uint8Array([]),
		
		// Payment proof
		"Payment Proof": (paymentProofType !== NO_PAYMENT_PROOF_TYPE) ? paymentProof : new Uint8Array([])
		
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_TRANSACTION_SIGNATURE_AND_PAYMENT_PROOF_MESSAGE_TYPE))["Signature"].at(-1);
	
	// Log transaction signature
	console.log("Transaction signature: " + Common.toHexString(signature));
	
	// Check if signature is invalid
	if(Secp256k1Zkp.verifySingleSignerSignature(signature, SlateKernel.signatureMessage(features, FEE, lockHeight, relativeHeight), Secp256k1Zkp.NO_PUBLIC_NONCE, publicKey, publicKey, true) !== true) {
	
		// Log message
		console.log("Invalid transaction signature");
		
		// Throw error
		throw "Failed running send transaction test";
	}
	
	// Log message
	console.log("Passed running send transaction test");
}

// Get MQS timestamp signature test
async function getMqsTimestampSignatureTest(hardwareWallet, extendedPrivateKey) {

	// Log message
	console.log("Running get MQS timestamp signature test");
	
	// Timestamp
	const TIMESTAMP = new BigNumber(Math.round(Math.random() * Common.UINT32_MAX_VALUE));
	
	// Log timestamp
	console.log("Using timestamp: " + TIMESTAMP.multipliedBy(Common.MILLISECONDS_IN_A_SECOND).toFixed());
	
	// Get MQS private key from the extended private key
	const mqsPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
	
	// Get timestamp hash
	const timestampHash = new Uint8Array(sha256.arrayBuffer((new TextEncoder()).encode(TIMESTAMP.multipliedBy(Common.MILLISECONDS_IN_A_SECOND).toFixed())));
	
	// Set expected MQS timestamp signature as the timestamp hash signed by the MQS private key
	const expectedMqsTimestampSignature = Secp256k1Zkp.createMessageHashSignature(timestampHash, mqsPrivateKey);
	
	// Get time zone offset
	const timeZoneOffset = (new Date()).getTimezoneOffset();
	
	// Log time zone offset
	console.log("Using time zone offset: " + timeZoneOffset.toFixed());
	
	// Get timestamp as a date
	const date = new Date((TIMESTAMP.toNumber() - timeZoneOffset * Common.SECONDS_IN_A_MINUTE) * Common.MILLISECONDS_IN_A_SECOND);
	
	// Log message
	console.log("Verify that the account index on the device is: " + ACCOUNT.toFixed());
	
	// Log message
	console.log("Verify that the timestamp's time and date on the device is: " + date.getUTCHours().toFixed().padStart(2, "0") + ":" + date.getUTCMinutes().toFixed().padStart(2, "0") + ":" + date.getUTCSeconds().toFixed().padStart(2, "0") + " on " + date.getUTCFullYear().toFixed() + "-" + (date.getUTCMonth() + 1).toFixed().padStart(2, "0") + "-" + date.getUTCDate().toFixed().padStart(2, "0") + " UTC" + ((timeZoneOffset > 0) ? "-" : "+") + Math.floor(Math.abs(timeZoneOffset) / Common.MINUTES_IN_AN_HOUR).toFixed().padStart(2, "0") + ":" + (Math.abs(timeZoneOffset) % Common.MINUTES_IN_AN_HOUR).toFixed().padStart(2, "0"));
	
	// Get the MQS challenge signature from the hardware wallet
	const mqsChallengeSignature = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_GET_MQS_CHALLENGE_SIGNATURE_MESSAGE_TYPE, {
				
		// Coin type
		"Coin Type": Consensus.getWalletType(),
		
		// Network type
		"Network Type": Consensus.getNetworkType(),
		
		// Account
		"Account": ACCOUNT,
		
		// Index
		"Index": INDEX,
		
		// Timestamp
		"Timestamp": TIMESTAMP.multipliedBy(Common.MILLISECONDS_IN_A_SECOND),
		
		// Time zone offset
		"Time Zone Offset": new BigNumber(timeZoneOffset)
	
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_MQS_CHALLENGE_SIGNATURE_MESSAGE_TYPE))["MQS Challenge Signature"].at(-1);
	
	// Log MQS timestamp signature
	console.log("MQS timestamp signature: " + Common.toHexString(mqsChallengeSignature));
	
	// Check if MQS timestamp signature is invalid
	if(Common.arraysAreEqual(mqsChallengeSignature, expectedMqsTimestampSignature) === false) {
	
		// Log message
		console.log("Invalid MQS timestamp signature");
		
		// Throw error
		throw "Failed running get MQS timestamp signature test";
	}
	
	// Log message
	console.log("Passed getting MQS timestamp signature test");
}

// Get MQS default challenge signature test
async function getMqsDefaultChallengeSignatureTest(hardwareWallet, extendedPrivateKey) {

	// Log message
	console.log("Running get MQS default challenge signature test");
	
	// Get MQS private key from the extended private key
	const mqsPrivateKey = await Crypto.addressKey(extendedPrivateKey, INDEX.toNumber());
	
	// Get default challenge hash
	const defaultChallengeHash = new Uint8Array(sha256.arrayBuffer((new TextEncoder()).encode(Mqs.DEFAULT_CHALLENGE)));
	
	// Set expected MQS default challenge signature as the default challenge hash signed by the MQS private key
	const expectedMqsDefaultChallengeSignature = Secp256k1Zkp.createMessageHashSignature(defaultChallengeHash, mqsPrivateKey);
	
	// Log message
	console.log("Verify that the account index on the device is: " + ACCOUNT.toFixed());
	
	// Get the MQS challenge signature from the hardware wallet
	const mqsChallengeSignature = (await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_GET_MQS_CHALLENGE_SIGNATURE_MESSAGE_TYPE, {
				
		// Coin type
		"Coin Type": Consensus.getWalletType(),
		
		// Network type
		"Network Type": Consensus.getNetworkType(),
		
		// Account
		"Account": ACCOUNT,
		
		// Index
		"Index": INDEX
	
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_MQS_CHALLENGE_SIGNATURE_MESSAGE_TYPE))["MQS Challenge Signature"].at(-1);
	
	// Log MQS default challenge signature
	console.log("MQS default challenge signature: " + Common.toHexString(mqsChallengeSignature));
	
	// Check if MQS default challenge signature is invalid
	if(Common.arraysAreEqual(mqsChallengeSignature, expectedMqsDefaultChallengeSignature) === false) {
	
		// Log message
		console.log("Invalid MQS default challenge signature");
		
		// Throw error
		throw "Failed running get MQS default challenge signature test";
	}
	
	// Log message
	console.log("Passed getting MQS default challenge signature test");
}

// Get login signature test
async function getLoginSignatureTest(hardwareWallet, extendedPrivateKey) {

	// Log message
	console.log("Running get login signature test");
	
	// Timestamp
	const TIMESTAMP = new BigNumber(Math.round(Math.random() * Common.UINT32_MAX_VALUE));
	
	// Log timestamp
	console.log("Using timestamp: " + TIMESTAMP.multipliedBy(Common.MILLISECONDS_IN_A_SECOND).toFixed());
	
	// Get login private key from the extended private key
	const loginPrivateKey = await Crypto.loginKey(extendedPrivateKey);
	
	// Get timestamp hash
	const timestampHash = new Uint8Array(sha256.arrayBuffer((new TextEncoder()).encode(TIMESTAMP.multipliedBy(Common.MILLISECONDS_IN_A_SECOND).toFixed())));
	
	// Set expected login public key to the login private key's public key
	const expectedLoginPublicKey = Secp256k1Zkp.publicKeyFromSecretKey(loginPrivateKey);
	
	// Set expected login signature as the timestamp hash signed by the login private key
	const expectedLoginSignature = Secp256k1Zkp.createMessageHashSignature(timestampHash, loginPrivateKey);
	
	// Get time zone offset
	const timeZoneOffset = (new Date()).getTimezoneOffset();
	
	// Log time zone offset
	console.log("Using time zone offset: " + timeZoneOffset.toFixed());
	
	// Get timestamp as a date
	const date = new Date((TIMESTAMP.toNumber() - timeZoneOffset * Common.SECONDS_IN_A_MINUTE) * Common.MILLISECONDS_IN_A_SECOND);
	
	// Log message
	console.log("Verify that the account index on the device is: " + ACCOUNT.toFixed());
	
	// Log message
	console.log("Verify that the time and date on the device is: " + date.getUTCHours().toFixed().padStart(2, "0") + ":" + date.getUTCMinutes().toFixed().padStart(2, "0") + ":" + date.getUTCSeconds().toFixed().padStart(2, "0") + " on " + date.getUTCFullYear().toFixed() + "-" + (date.getUTCMonth() + 1).toFixed().padStart(2, "0") + "-" + date.getUTCDate().toFixed().padStart(2, "0") + " UTC" + ((timeZoneOffset > 0) ? "-" : "+") + Math.floor(Math.abs(timeZoneOffset) / Common.MINUTES_IN_AN_HOUR).toFixed().padStart(2, "0") + ":" + (Math.abs(timeZoneOffset) % Common.MINUTES_IN_AN_HOUR).toFixed().padStart(2, "0"));
	
	// Get the login challenge signature from the hardware wallet
	const response = await hardwareWallet.send(HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_GET_LOGIN_CHALLENGE_SIGNATURE_MESSAGE_TYPE, {
				
		// Coin type
		"Coin Type": Consensus.getWalletType(),
		
		// Network type
		"Network Type": Consensus.getNetworkType(),
		
		// Account
		"Account": ACCOUNT,
		
		// Timestamp
		"Timestamp": TIMESTAMP.multipliedBy(Common.MILLISECONDS_IN_A_SECOND),
		
		// Time zone offset
		"Time Zone Offset": new BigNumber(timeZoneOffset)
	
	}, HardwareWalletDefinitions.MIMBLEWIMBLE_COIN_LOGIN_CHALLENGE_SIGNATURE_MESSAGE_TYPE);
	
	// Get login public key from response
	const loginPublicKey = response["Login Public Key"].at(-1);
	
	// Get login challenge signature from response
	const loginChallengeSignature = response["Login Challenge Signature"].at(-1);
	
	// Log login public key
	console.log("Login public key: " + Common.toHexString(loginPublicKey));
	
	// Check if login public key is invalid
	if(Common.arraysAreEqual(loginPublicKey, expectedLoginPublicKey) === false) {
	
		// Log message
		console.log("Invalid login public key");
		
		// Throw error
		throw "Failed running get login signature test";
	}
	
	// Log login signature
	console.log("Login signature: " + Common.toHexString(loginChallengeSignature));
	
	// Check if login signature is invalid
	if(Common.arraysAreEqual(loginChallengeSignature, expectedLoginSignature) === false) {
	
		// Log message
		console.log("Invalid login signature");
		
		// Throw error
		throw "Failed running get login signature test";
	}
	
	// Log message
	console.log("Passed getting login signature test");
}


// Export USB transport
module["exports"] = UsbTransport;
