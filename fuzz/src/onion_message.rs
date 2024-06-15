// Imports that need to be added manually
use bech32::u5;
use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::RecoverableSignature;
use bitcoin::secp256k1::schnorr;
use bitcoin::secp256k1::{self, PublicKey, Scalar, Secp256k1, SecretKey};

use lightning::blinded_path::message::{MessageContext, OffersContext};
use lightning::blinded_path::{BlindedPath, EmptyNodeIdLookUp};
use lightning::ln::features::InitFeatures;
use lightning::ln::msgs::{self, DecodeError, OnionMessageHandler};
use lightning::ln::script::ShutdownScript;
use lightning::offers::invoice::UnsignedBolt12Invoice;
use lightning::offers::invoice_request::UnsignedInvoiceRequest;
use lightning::onion_message::messenger::{
	CustomOnionMessageHandler, Destination, MessageRouter, OnionMessagePath, OnionMessenger,
	PendingOnionMessage, Responder, ResponseInstruction,
};
use lightning::onion_message::offers::{OffersMessage, OffersMessageHandler};
use lightning::onion_message::packet::OnionMessageContents;
use lightning::sign::{EntropySource, KeyMaterial, NodeSigner, Recipient, SignerProvider};
use lightning::util::logger::Logger;
use lightning::util::ser::{Readable, Writeable, Writer};
use lightning::util::test_channel_signer::TestChannelSigner;

use crate::utils::test_logger;

use std::io::{self, Cursor};
use std::sync::atomic::{AtomicU64, Ordering};

#[inline]
/// Actual fuzz test, method signature and name are fixed
pub fn do_test<L: Logger>(data: &[u8], logger: &L) {
	if let Ok(msg) = <msgs::OnionMessage as Readable>::read(&mut Cursor::new(data)) {
		let mut secret_bytes = [1; 32];
		secret_bytes[31] = 2;
		let secret = SecretKey::from_slice(&secret_bytes).unwrap();
		let keys_manager = KeyProvider { node_secret: secret, counter: AtomicU64::new(0) };
		let node_id_lookup = EmptyNodeIdLookUp {};
		let message_router = TestMessageRouter {};
		let offers_msg_handler = TestOffersMessageHandler {};
		let custom_msg_handler = TestCustomMessageHandler {};
		let onion_messenger = OnionMessenger::new(
			&keys_manager,
			&keys_manager,
			logger,
			&node_id_lookup,
			&message_router,
			&offers_msg_handler,
			&custom_msg_handler,
		);

		let peer_node_id = {
			let mut secret_bytes = [0; 32];
			secret_bytes[31] = 2;
			let secret = SecretKey::from_slice(&secret_bytes).unwrap();
			PublicKey::from_secret_key(&Secp256k1::signing_only(), &secret)
		};

		let mut features = InitFeatures::empty();
		features.set_onion_messages_optional();
		let init = msgs::Init { features, networks: None, remote_network_address: None };

		onion_messenger.peer_connected(&peer_node_id, &init, false).unwrap();
		onion_messenger.handle_onion_message(&peer_node_id, &msg);
	}
}

/// Method that needs to be added manually, {name}_test
pub fn onion_message_test<Out: test_logger::Output>(data: &[u8], out: Out) {
	let logger = test_logger::TestLogger::new("".to_owned(), out);
	do_test(data, &logger);
}

/// Method that needs to be added manually, {name}_run
#[no_mangle]
pub extern "C" fn onion_message_run(data: *const u8, datalen: usize) {
	let logger = test_logger::TestLogger::new("".to_owned(), test_logger::DevNull {});
	do_test(unsafe { std::slice::from_raw_parts(data, datalen) }, &logger);
}

struct TestMessageRouter {}

impl MessageRouter for TestMessageRouter {
	fn find_path(
		&self, _sender: PublicKey, _peers: Vec<PublicKey>, destination: Destination,
	) -> Result<OnionMessagePath, ()> {
		Ok(OnionMessagePath { intermediate_nodes: vec![], destination, first_node_addresses: None })
	}

	fn create_blinded_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, _recipient: PublicKey, _recipient_data: Option<MessageContext>,
		_peers: Vec<PublicKey>, _secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPath>, ()> {
		unreachable!()
	}
}

struct TestOffersMessageHandler {}

impl OffersMessageHandler for TestOffersMessageHandler {
	fn handle_message(
		&self, _message: OffersMessage, _responder: Option<Responder>, _context: OffersContext,
	) -> ResponseInstruction<OffersMessage> {
		ResponseInstruction::NoResponse
	}
}

#[derive(Debug)]
struct TestCustomMessage {}

const CUSTOM_MESSAGE_TYPE: u64 = 4242;
const CUSTOM_MESSAGE_CONTENTS: [u8; 32] = [42; 32];

impl OnionMessageContents for TestCustomMessage {
	fn tlv_type(&self) -> u64 {
		CUSTOM_MESSAGE_TYPE
	}
	fn msg_type(&self) -> &'static str {
		"Custom Message"
	}
}

impl Writeable for TestCustomMessage {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		Ok(CUSTOM_MESSAGE_CONTENTS.write(w)?)
	}
}

struct TestCustomMessageHandler {}

impl CustomOnionMessageHandler for TestCustomMessageHandler {
	type CustomMessage = TestCustomMessage;
	fn handle_custom_message(
		&self, message: Self::CustomMessage, responder: Option<Responder>, _context: Vec<u8>,
	) -> ResponseInstruction<Self::CustomMessage> {
		match responder {
			Some(responder) => responder.respond(message),
			None => ResponseInstruction::NoResponse,
		}
	}
	fn read_custom_message<R: io::Read>(
		&self, _message_type: u64, buffer: &mut R,
	) -> Result<Option<Self::CustomMessage>, msgs::DecodeError> {
		let mut buf = Vec::new();
		buffer.read_to_end(&mut buf)?;
		return Ok(Some(TestCustomMessage {}));
	}
	fn release_pending_custom_messages(&self) -> Vec<PendingOnionMessage<Self::CustomMessage>> {
		vec![]
	}
}

pub struct VecWriter(pub Vec<u8>);
impl Writer for VecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
}
struct KeyProvider {
	node_secret: SecretKey,
	counter: AtomicU64,
}

impl EntropySource for KeyProvider {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let ctr = self.counter.fetch_add(1, Ordering::Relaxed);
		#[rustfmt::skip]
		let random_bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			(ctr >> 8*7) as u8, (ctr >> 8*6) as u8, (ctr >> 8*5) as u8, (ctr >> 8*4) as u8,
			(ctr >> 8*3) as u8, (ctr >> 8*2) as u8, (ctr >> 8*1) as u8, 14, (ctr >> 8*0) as u8];
		random_bytes
	}
}

impl NodeSigner for KeyProvider {
	fn get_node_id(&self, recipient: Recipient) -> Result<PublicKey, ()> {
		let node_secret = match recipient {
			Recipient::Node => Ok(&self.node_secret),
			Recipient::PhantomNode => Err(()),
		}?;
		Ok(PublicKey::from_secret_key(&Secp256k1::signing_only(), node_secret))
	}

	fn ecdh(
		&self, recipient: Recipient, other_key: &PublicKey, tweak: Option<&Scalar>,
	) -> Result<SharedSecret, ()> {
		let mut node_secret = match recipient {
			Recipient::Node => Ok(self.node_secret.clone()),
			Recipient::PhantomNode => Err(()),
		}?;
		if let Some(tweak) = tweak {
			node_secret = node_secret.mul_tweak(tweak).map_err(|_| ())?;
		}
		Ok(SharedSecret::new(other_key, &node_secret))
	}

	fn get_inbound_payment_key_material(&self) -> KeyMaterial {
		unreachable!()
	}

	fn sign_invoice(
		&self, _hrp_bytes: &[u8], _invoice_data: &[u5], _recipient: Recipient,
	) -> Result<RecoverableSignature, ()> {
		unreachable!()
	}

	fn sign_bolt12_invoice_request(
		&self, _invoice_request: &UnsignedInvoiceRequest,
	) -> Result<schnorr::Signature, ()> {
		unreachable!()
	}

	fn sign_bolt12_invoice(
		&self, _invoice: &UnsignedBolt12Invoice,
	) -> Result<schnorr::Signature, ()> {
		unreachable!()
	}

	fn sign_gossip_message(
		&self, _msg: lightning::ln::msgs::UnsignedGossipMessage,
	) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		unreachable!()
	}
}

impl SignerProvider for KeyProvider {
	type EcdsaSigner = TestChannelSigner;
	#[cfg(taproot)]
	type TaprootSigner = TestChannelSigner;

	fn generate_channel_keys_id(
		&self, _inbound: bool, _channel_value_satoshis: u64, _user_channel_id: u128,
	) -> [u8; 32] {
		unreachable!()
	}

	fn derive_channel_signer(
		&self, _channel_value_satoshis: u64, _channel_keys_id: [u8; 32],
	) -> Self::EcdsaSigner {
		unreachable!()
	}

	fn read_chan_signer(&self, _data: &[u8]) -> Result<TestChannelSigner, DecodeError> {
		unreachable!()
	}

	fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
		unreachable!()
	}

	fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
		unreachable!()
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::hashes::hex::FromHex;
	use lightning::util::logger::{Logger, Record};
	use std::collections::HashMap;
	use std::sync::Mutex;

	struct TrackingLogger {
		/// (module, message) -> count
		pub lines: Mutex<HashMap<(String, String), usize>>,
	}
	impl Logger for TrackingLogger {
		fn log(&self, record: Record) {
			let mut lines_lock = self.lines.lock().unwrap();
			let key = (record.module_path.to_string(), format!("{}", record.args));
			*lines_lock.entry(key).or_insert(0) += 1;
			println!(
				"{:<5} [{} : {}, {}] {}",
				record.level.to_string(),
				record.module_path,
				record.file,
				record.line,
				record.args
			);
		}
	}

	#[test]
	fn test_no_onion_message_breakage() {
		let one_hop_om = "\
			020000000000000000000000000000000000000000000000000000000000000e01055600020000000000000\
			000000000000000000000000000000000000000000000000e01ae0276020000000000000000000000000000\
			000000000000000000000000000000000002020000000000000000000000000000000000000000000000000\
			000000000000e0101022a0000000000000000000000000000014551231950b75fc4402da1732fc9bebf0010\
			9500000000000000000000000000000004106d000000000000000000000000000000fd1092202a2a2a2a2a2\
			a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a0000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000005600000000000000000000000000000000000000000000\
			000000000000000000";
		let logger = TrackingLogger { lines: Mutex::new(HashMap::new()) };
		super::do_test(&<Vec<u8>>::from_hex(one_hop_om).unwrap(), &logger);
		{
			let log_entries = logger.lines.lock().unwrap();
			assert_eq!(
				log_entries.get(&(
					"lightning::onion_message::messenger".to_string(),
					"Received an onion message with a reply_path: Custom(TestCustomMessage)"
						.to_string()
				)),
				Some(&1)
			);
			assert_eq!(log_entries.get(&("lightning::onion_message::messenger".to_string(),
						"Constructing onion message when responding with Custom Message to an onion message: TestCustomMessage".to_string())), Some(&1));
			assert_eq!(log_entries.get(&("lightning::onion_message::messenger".to_string(),
						"Buffered onion message when responding with Custom Message to an onion message".to_string())), Some(&1));
		}

		let two_unblinded_hops_om = "\
			020000000000000000000000000000000000000000000000000000000000000e01055600020000000000000\
			000000000000000000000000000000000000000000000000e01350433042102020202020202020202020202\
			02020202020202020202020202020202020202026d000000000000000000000000000000eb0000000000000\
			000000000000000000000000000000000000000000000000036041096000000000000000000000000000000\
			fd1092202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000004800000000000000000000000000000000000000000000\
			000000000000000000";
		let logger = TrackingLogger { lines: Mutex::new(HashMap::new()) };
		super::do_test(&<Vec<u8>>::from_hex(two_unblinded_hops_om).unwrap(), &logger);
		{
			let log_entries = logger.lines.lock().unwrap();
			assert_eq!(log_entries.get(&("lightning::onion_message::messenger".to_string(), "Forwarding an onion message to peer 020202020202020202020202020202020202020202020202020202020202020202".to_string())), Some(&1));
		}

		let two_unblinded_two_blinded_om = "\
			020000000000000000000000000000000000000000000000000000000000000e01055600020000000000000\
			000000000000000000000000000000000000000000000000e01350433042102020202020202020202020202\
			02020202020202020202020202020202020202026d0000000000000000000000000000009e0000000000000\
			000000000000000000000000000000000000000000000000058045604210203030303030303030303030303\
			030303030303030303030303030303030303020821020000000000000000000000000000000000000000000\
			000000000000000000e0196000000000000000000000000000000e900000000000000000000000000000000\
			000000000000000000000000000000350433042102040404040404040404040404040404040404040404040\
			4040404040404040402ca000000000000000000000000000000420000000000000000000000000000000000\
			00000000000000000000000000003604103f000000000000000000000000000000fd1092202a2a2a2a2a2a2\
			a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000004800000000000000000000000000000000000000000000\
			000000000000000000";
		let logger = TrackingLogger { lines: Mutex::new(HashMap::new()) };
		super::do_test(&<Vec<u8>>::from_hex(two_unblinded_two_blinded_om).unwrap(), &logger);
		{
			let log_entries = logger.lines.lock().unwrap();
			assert_eq!(log_entries.get(&("lightning::onion_message::messenger".to_string(), "Forwarding an onion message to peer 020202020202020202020202020202020202020202020202020202020202020202".to_string())), Some(&1));
		}

		let three_blinded_om = "\
			020000000000000000000000000000000000000000000000000000000000000e01055600020000000000000\
			000000000000000000000000000000000000000000000000e01350433042102020202020202020202020202\
			02020202020202020202020202020202020202026d000000000000000000000000000000b20000000000000\
			000000000000000000000000000000000000000000000000035043304210203030303030303030303030303\
			030303030303030303030303030303030303029600000000000000000000000000000033000000000000000\
			000000000000000000000000000000000000000000000003604104e000000000000000000000000000000fd\
			1092202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a00000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
			000000000000000000000000000000000000000004800000000000000000000000000000000000000000000\
			000000000000000000";
		let logger = TrackingLogger { lines: Mutex::new(HashMap::new()) };
		super::do_test(&<Vec<u8>>::from_hex(three_blinded_om).unwrap(), &logger);
		{
			let log_entries = logger.lines.lock().unwrap();
			assert_eq!(log_entries.get(&("lightning::onion_message::messenger".to_string(), "Forwarding an onion message to peer 020202020202020202020202020202020202020202020202020202020202020202".to_string())), Some(&1));
		}
	}
}
