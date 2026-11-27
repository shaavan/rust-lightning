// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Exercises production dummy policies by linking lightning as a dependency without cfg(test).
//! Run with `--features _test_utils`; `_externalize_tests` uses fixed constructor policies.

#![cfg(not(feature = "_externalize_tests"))]

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use lightning::blinded_path::payment::{
	BlindedPaymentPath, Bolt12RefundContext, DummyTlvs, ForwardTlvs, PaymentConstraints,
	PaymentContext, PaymentForwardNode, PaymentRelay, ReceiveTlvs,
};
use lightning::blinded_path::IntroductionNode;
use lightning::ln::channel_state::ChannelDetails;
use lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA;
use lightning::ln::functional_test_utils::{
	create_announced_chan_between_nodes, create_chanmon_cfgs, create_network, create_node_cfgs,
	create_node_chanmgrs, create_unannounced_chan_between_nodes_with_value, Node,
};
use lightning::routing::router::{Router, DEFAULT_PAYMENT_DUMMY_HOPS};
use lightning::sign::{NodeSigner, ReceiveAuthKey};
use lightning::types::features::BlindedHopFeatures;
use lightning::types::payment::PaymentSecret;

/// Checks known derivation outputs through the public constructor, including the reversal from
/// receiving-hop order into path order. Fixed test policies cannot satisfy this expectation.
#[test]
fn constructor_uses_derived_dummy_policies() {
	let secp_ctx = Secp256k1::new();
	let mut secret = [0; 32];
	secret[31] = 1;
	let introduction =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&secret).unwrap());
	let (dummies, _) = DummyTlvs::new_dummy_tail_from_receive_constraints(
		3,
		PaymentConstraints { max_cltv_expiry: 1_000, htlc_minimum_msat: 1 },
		ReceiveAuthKey([42; 32]),
		introduction,
	)
	.unwrap();
	let policies: Vec<_> = dummies
		.iter()
		.map(|dummy| {
			let relay = dummy.payment_relay;
			(relay.cltv_expiry_delta, relay.fee_proportional_millionths, relay.fee_base_msat)
		})
		.collect();
	assert_eq!(policies, vec![(80, 10, 0), (144, 1, 1_000), (80, 0, 0)]);
}

/// Keeps forwarding policy and channel limits constant while varying invoice secrets, expiry,
/// metadata, and channel aliases. Only encrypted path data should change between these samples.
fn assert_stable_payinfo(
	recipient: &Node, first_hops: Vec<ChannelDetails>, introduction: PublicKey, real_hops: usize,
) {
	let secp_ctx = Secp256k1::new();
	let receive_tlvs = |sample: u8| {
		let mut metadata = std::collections::BTreeMap::new();
		metadata.insert(42, vec![sample]);
		ReceiveTlvs {
			payment_secret: PaymentSecret([sample; 32]),
			payment_constraints: PaymentConstraints {
				max_cltv_expiry: 100_000 + sample as u32,
				htlc_minimum_msat: 1,
			},
			payment_context: PaymentContext::Bolt12Refund(Bolt12RefundContext {
				payment_metadata: Some(metadata),
				invoice_request: None,
			}),
		}
	};
	let create_path = |sample: u8| {
		let mut channels = first_hops.clone();
		for channel in &mut channels {
			// Aliases identify channels, but the dummy policy should depend on the introduction node.
			channel.inbound_scid_alias = Some(1_000_000 + sample as u64);
		}
		let mut paths = recipient
			.router
			.create_blinded_payment_paths(
				recipient.node.get_our_node_id(),
				recipient.keys_manager.get_receive_auth_key(),
				channels,
				receive_tlvs(sample),
				Some(10_000),
				&secp_ctx,
			)
			.unwrap();
		assert_eq!(paths.len(), 1);
		paths.pop().unwrap()
	};
	let expected = create_path(0);
	// Build a reference with the intended introduction identity explicitly. This also detects
	// a router that produces stable policies but derives them from the wrong node or key.
	let receive_key = recipient.keys_manager.get_receive_auth_key();
	let tlvs = receive_tlvs(0);
	let (dummies, constraints) = DummyTlvs::new_dummy_tail_from_receive_constraints(
		DEFAULT_PAYMENT_DUMMY_HOPS,
		tlvs.payment_constraints,
		receive_key,
		introduction,
	)
	.unwrap();
	let forward_nodes: Vec<_> = first_hops
		.iter()
		.map(|channel| {
			let relay =
				PaymentRelay::try_from(channel.counterparty.forwarding_info.unwrap()).unwrap();
			PaymentForwardNode {
				node_id: introduction,
				htlc_maximum_msat: channel.inbound_htlc_maximum_msat.unwrap_or(u64::MAX),
				tlvs: ForwardTlvs {
					short_channel_id: channel.get_inbound_payment_scid().unwrap(),
					payment_relay: relay,
					payment_constraints: PaymentConstraints {
						max_cltv_expiry: constraints.max_cltv_expiry
							+ relay.cltv_expiry_delta as u32,
						htlc_minimum_msat: channel.inbound_htlc_minimum_msat.unwrap_or(0),
					},
					features: BlindedHopFeatures::empty(),
					next_blinding_override: None,
				},
			}
		})
		.collect();
	let reference = BlindedPaymentPath::new_with_dummy_hops(
		&forward_nodes,
		recipient.node.get_our_node_id(),
		&dummies,
		receive_key,
		tlvs,
		u64::MAX,
		MIN_FINAL_CLTV_EXPIRY_DELTA,
		recipient.keys_manager,
		&secp_ctx,
	)
	.unwrap();
	assert_eq!(expected.payinfo, reference.payinfo);
	assert_eq!(expected.introduction_node(), &IntroductionNode::NodeId(introduction));
	assert_eq!(expected.blinded_hops().len(), real_hops + DEFAULT_PAYMENT_DUMMY_HOPS + 1);
	for sample in 1..32 {
		let path = create_path(sample);
		// Invoice-specific data and fresh path entropy must not provide fresh policy samples.
		assert_eq!(path.payinfo, expected.payinfo);
		assert_eq!(path.introduction_node(), expected.introduction_node());
		assert_eq!(path.blinded_hops().len(), expected.blinded_hops().len());
		assert_ne!(path.blinding_point(), expected.blinding_point());
		assert_ne!(path.blinded_hops(), expected.blinded_hops());
	}
}

/// A private recipient's forwarding peer must select the same dummy policies across invoices.
#[test]
fn forwarding_introduction_keeps_payinfo_stable() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_unannounced_chan_between_nodes_with_value(&nodes, 0, 1, 1_000_000, 0);
	assert_stable_payinfo(
		&nodes[1],
		nodes[1].node.list_usable_channels(),
		nodes[0].node.get_our_node_id(),
		1,
	);
}

/// An announced recipient can introduce its own path when no forwarding channels are supplied.
#[test]
fn recipient_introduction_keeps_payinfo_stable() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);
	assert_stable_payinfo(&nodes[1], Vec::new(), nodes[1].node.get_our_node_id(), 0);
}
