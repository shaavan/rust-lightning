// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests that test the payment retry logic in ChannelManager, including various edge-cases around
//! serialization ordering between ChannelManager/ChannelMonitors and ensuring we can still retry
//! payments thereafter.

use chain::{Confirm, Watch};
use chain::channelmonitor::ChannelMonitor;
use ln::{PaymentPreimage, PaymentHash};
use ln::channelmanager::{ChannelManager, ChannelManagerReadArgs, PaymentId, PaymentSendFailure};
use ln::features::InitFeatures;
use ln::msgs;
use ln::msgs::{ChannelMessageHandler, ErrorAction};
use util::events::{ClosureReason, Event, MessageSendEvent, MessageSendEventsProvider};
use util::test_utils;
use util::errors::APIError;
use util::enforcing_trait_impls::EnforcingSigner;
use util::ser::{ReadableArgs, Writeable};

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;

use prelude::*;

use ln::functional_test_utils::*;

#[test]
fn retry_single_path_payment() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let _chan_0 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let _chan_1 = create_announced_chan_between_nodes(&nodes, 2, 1, InitFeatures::known(), InitFeatures::known());
	// Rebalance to find a route
	send_payment(&nodes[2], &vec!(&nodes[1])[..], 3_000_000);

	let (route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 100_000);

	// Rebalance so that the first hop fails.
	send_payment(&nodes[1], &vec!(&nodes[2])[..], 2_000_000);

	// Make sure the payment fails on the first hop.
	let payment_id = nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable!(&nodes[1]);
	let htlc_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[1], 1);
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], htlc_updates.commitment_signed, false);
	expect_payment_failed!(nodes[0], payment_hash, false);

	// Rebalance the channel so the retry succeeds.
	send_payment(&nodes[2], &vec!(&nodes[1])[..], 3_000_000);

	// Mine two blocks (we expire retries after 3, so this will check that we don't expire early)
	connect_blocks(&nodes[0], 2);

	// Retry the payment and make sure it succeeds.
	nodes[0].node.retry_payment(&route, payment_id).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[1], &nodes[2]], 100_000, payment_hash, Some(payment_secret), events.pop().unwrap(), true, None);
	claim_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], false, payment_preimage);
}

#[test]
fn mpp_failure() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 2, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;

	let (mut route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(&nodes[0], nodes[3], 100000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0][0].pubkey = nodes[1].node.get_our_node_id();
	route.paths[0][0].short_channel_id = chan_1_id;
	route.paths[0][1].short_channel_id = chan_3_id;
	route.paths[1][0].pubkey = nodes[2].node.get_our_node_id();
	route.paths[1][0].short_channel_id = chan_2_id;
	route.paths[1][1].short_channel_id = chan_4_id;
	send_along_route_with_secret(&nodes[0], route, &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], 200_000, payment_hash, payment_secret);
	fail_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], false, payment_hash);
}

#[test]
fn mpp_retry() {
	let chanmon_cfgs = create_chanmon_cfgs(4);
	let node_cfgs = create_node_cfgs(4, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(4, &node_cfgs, &[None, None, None, None]);
	let nodes = create_network(4, &node_cfgs, &node_chanmgrs);

	let chan_1_id = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_2_id = create_announced_chan_between_nodes(&nodes, 0, 2, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_3_id = create_announced_chan_between_nodes(&nodes, 1, 3, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	let chan_4_id = create_announced_chan_between_nodes(&nodes, 3, 2, InitFeatures::known(), InitFeatures::known()).0.contents.short_channel_id;
	// Rebalance
	send_payment(&nodes[3], &vec!(&nodes[2])[..], 1_500_000);

	let (mut route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[3], 1_000_000);
	let path = route.paths[0].clone();
	route.paths.push(path);
	route.paths[0][0].pubkey = nodes[1].node.get_our_node_id();
	route.paths[0][0].short_channel_id = chan_1_id;
	route.paths[0][1].short_channel_id = chan_3_id;
	route.paths[1][0].pubkey = nodes[2].node.get_our_node_id();
	route.paths[1][0].short_channel_id = chan_2_id;
	route.paths[1][1].short_channel_id = chan_4_id;

	// Initiate the MPP payment.
	let payment_id = nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 2); // one monitor per path
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 2);

	// Pass half of the payment along the success path.
	let success_path_msgs = events.remove(0);
	pass_along_path(&nodes[0], &[&nodes[1], &nodes[3]], 2_000_000, payment_hash, Some(payment_secret), success_path_msgs, false, None);

	// Add the HTLC along the first hop.
	let fail_path_msgs_1 = events.remove(0);
	let (update_add, commitment_signed) = match fail_path_msgs_1 {
		MessageSendEvent::UpdateHTLCs { node_id: _, updates: msgs::CommitmentUpdate { ref update_add_htlcs, ref update_fulfill_htlcs, ref update_fail_htlcs, ref update_fail_malformed_htlcs, ref update_fee, ref commitment_signed } } => {
			assert_eq!(update_add_htlcs.len(), 1);
			assert!(update_fail_htlcs.is_empty());
			assert!(update_fulfill_htlcs.is_empty());
			assert!(update_fail_malformed_htlcs.is_empty());
			assert!(update_fee.is_none());
			(update_add_htlcs[0].clone(), commitment_signed.clone())
		},
		_ => panic!("Unexpected event"),
	};
	nodes[2].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &update_add);
	commitment_signed_dance!(nodes[2], nodes[0], commitment_signed, false);

	// Attempt to forward the payment and complete the 2nd path's failure.
	expect_pending_htlcs_forwardable!(&nodes[2]);
	expect_pending_htlcs_forwardable!(&nodes[2]);
	let htlc_updates = get_htlc_update_msgs!(nodes[2], nodes[0].node.get_our_node_id());
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[2], 1);
	nodes[0].node.handle_update_fail_htlc(&nodes[2].node.get_our_node_id(), &htlc_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[2], htlc_updates.commitment_signed, false);
	expect_payment_failed!(nodes[0], payment_hash, false);

	// Rebalance the channel so the second half of the payment can succeed.
	send_payment(&nodes[3], &vec!(&nodes[2])[..], 1_500_000);

	// Make sure it errors as expected given a too-large amount.
	if let Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError { err })) = nodes[0].node.retry_payment(&route, payment_id) {
		assert!(err.contains("over total_payment_amt_msat"));
	} else { panic!("Unexpected error"); }

	// Make sure it errors as expected given the wrong payment_id.
	if let Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError { err })) = nodes[0].node.retry_payment(&route, PaymentId([0; 32])) {
		assert!(err.contains("not found"));
	} else { panic!("Unexpected error"); }

	// Retry the second half of the payment and make sure it succeeds.
	let mut path = route.clone();
	path.paths.remove(0);
	nodes[0].node.retry_payment(&path, payment_id).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[2], &nodes[3]], 2_000_000, payment_hash, Some(payment_secret), events.pop().unwrap(), true, None);
	claim_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[3]], &[&nodes[2], &nodes[3]]], false, payment_preimage);
}

#[test]
fn retry_expired_payment() {
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let _chan_0 = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	let _chan_1 = create_announced_chan_between_nodes(&nodes, 2, 1, InitFeatures::known(), InitFeatures::known());
	// Rebalance to find a route
	send_payment(&nodes[2], &vec!(&nodes[1])[..], 3_000_000);

	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 100_000);

	// Rebalance so that the first hop fails.
	send_payment(&nodes[1], &vec!(&nodes[2])[..], 2_000_000);

	// Make sure the payment fails on the first hop.
	let payment_id = nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let mut payment_event = SendEvent::from_event(events.pop().unwrap());
	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	check_added_monitors!(nodes[1], 0);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false);
	expect_pending_htlcs_forwardable!(nodes[1]);
	expect_pending_htlcs_forwardable!(&nodes[1]);
	let htlc_updates = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());
	assert!(htlc_updates.update_add_htlcs.is_empty());
	assert_eq!(htlc_updates.update_fail_htlcs.len(), 1);
	assert!(htlc_updates.update_fulfill_htlcs.is_empty());
	assert!(htlc_updates.update_fail_malformed_htlcs.is_empty());
	check_added_monitors!(nodes[1], 1);
	nodes[0].node.handle_update_fail_htlc(&nodes[1].node.get_our_node_id(), &htlc_updates.update_fail_htlcs[0]);
	commitment_signed_dance!(nodes[0], nodes[1], htlc_updates.commitment_signed, false);
	expect_payment_failed!(nodes[0], payment_hash, false);

	// Mine blocks so the payment will have expired.
	connect_blocks(&nodes[0], 3);

	// Retry the payment and make sure it errors as expected.
	if let Err(PaymentSendFailure::ParameterError(APIError::APIMisuseError { err })) = nodes[0].node.retry_payment(&route, payment_id) {
		assert!(err.contains("not found"));
	} else {
		panic!("Unexpected error");
	}
}

#[test]
fn no_pending_leak_on_initial_send_failure() {
	// In an earlier version of our payment tracking, we'd have a retry entry even when the initial
	// HTLC for payment failed to send due to local channel errors (e.g. peer disconnected). In this
	// case, the user wouldn't have a PaymentId to retry the payment with, but we'd think we have a
	// pending payment forever and never time it out.
	// Here we test exactly that - retrying a payment when a peer was disconnected on the first
	// try, and then check that no pending payment is being tracked.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());

	let (route, payment_hash, _, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[1], 100_000);

	nodes[0].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);
	nodes[1].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	unwrap_send_err!(nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)),
		true, APIError::ChannelUnavailable { ref err },
		assert_eq!(err, "Peer for first hop currently disconnected/pending monitor update!"));

	assert!(!nodes[0].node.has_pending_payments());
}

fn do_retry_with_no_persist(confirm_before_reload: bool) {
	// If we send a pending payment and `send_payment` returns success, we should always either
	// return a payment failure event or a payment success event, and on failure the payment should
	// be retryable.
	//
	// In order to do so when the ChannelManager isn't immediately persisted (which is normal - its
	// always persisted asynchronously), the ChannelManager has to reload some payment data from
	// ChannelMonitor(s) in some cases. This tests that reloading.
	//
	// `confirm_before_reload` confirms the channel-closing commitment transaction on-chain prior
	// to reloading the ChannelManager, increasing test coverage in ChannelMonitor HTLC tracking
	// which has separate codepaths for "commitment transaction already confirmed" and not.
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[None, None, None]);
	let persister: test_utils::TestPersister;
	let new_chain_monitor: test_utils::TestChainMonitor;
	let nodes_0_deserialized: ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>;
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);

	let (_, _, chan_id, funding_tx) = create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	create_announced_chan_between_nodes(&nodes, 1, 2, InitFeatures::known(), InitFeatures::known());

	// Serialize the ChannelManager prior to sending payments
	let nodes_0_serialized = nodes[0].node.encode();

	// Send two payments - one which will get to nodes[2] and will be claimed, one which we'll time
	// out and retry.
	let (route, payment_hash, payment_preimage, payment_secret) = get_route_and_payment_hash!(nodes[0], nodes[2], 1_000_000);
	let (payment_preimage_1, _, _, payment_id_1) = send_along_route(&nodes[0], route.clone(), &[&nodes[1], &nodes[2]], 1_000_000);
	let payment_id = nodes[0].node.send_payment(&route, payment_hash, &Some(payment_secret)).unwrap();
	check_added_monitors!(nodes[0], 1);

	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	let payment_event = SendEvent::from_event(events.pop().unwrap());
	assert_eq!(payment_event.node_id, nodes[1].node.get_our_node_id());

	// We relay the payment to nodes[1] while its disconnected from nodes[2], causing the payment
	// to be returned immediately to nodes[0], without having nodes[2] fail the inbound payment
	// which would prevent retry.
	nodes[1].node.peer_disconnected(&nodes[2].node.get_our_node_id(), false);
	nodes[2].node.peer_disconnected(&nodes[1].node.get_our_node_id(), false);

	nodes[1].node.handle_update_add_htlc(&nodes[0].node.get_our_node_id(), &payment_event.msgs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], payment_event.commitment_msg, false, true);
	// nodes[1] now immediately fails the HTLC as the next-hop channel is disconnected
	let _ = get_htlc_update_msgs!(nodes[1], nodes[0].node.get_our_node_id());

	reconnect_nodes(&nodes[1], &nodes[2], (false, false), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (false, false));

	let as_commitment_tx = get_local_commitment_txn!(nodes[0], chan_id)[0].clone();
	if confirm_before_reload {
		mine_transaction(&nodes[0], &as_commitment_tx);
		nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	}

	// The ChannelMonitor should always be the latest version, as we're required to persist it
	// during the `commitment_signed_dance!()`.
	let mut chan_0_monitor_serialized = test_utils::TestVecWriter(Vec::new());
	get_monitor!(nodes[0], chan_id).write(&mut chan_0_monitor_serialized).unwrap();

	persister = test_utils::TestPersister::new();
	let keys_manager = &chanmon_cfgs[0].keys_manager;
	new_chain_monitor = test_utils::TestChainMonitor::new(Some(nodes[0].chain_source), nodes[0].tx_broadcaster.clone(), nodes[0].logger, node_cfgs[0].fee_estimator, &persister, keys_manager);
	nodes[0].chain_monitor = &new_chain_monitor;
	let mut chan_0_monitor_read = &chan_0_monitor_serialized.0[..];
	let (_, mut chan_0_monitor) = <(BlockHash, ChannelMonitor<EnforcingSigner>)>::read(
		&mut chan_0_monitor_read, keys_manager).unwrap();
	assert!(chan_0_monitor_read.is_empty());

	let mut nodes_0_read = &nodes_0_serialized[..];
	let (_, nodes_0_deserialized_tmp) = {
		let mut channel_monitors = HashMap::new();
		channel_monitors.insert(chan_0_monitor.get_funding_txo().0, &mut chan_0_monitor);
		<(BlockHash, ChannelManager<EnforcingSigner, &test_utils::TestChainMonitor, &test_utils::TestBroadcaster, &test_utils::TestKeysInterface, &test_utils::TestFeeEstimator, &test_utils::TestLogger>)>::read(&mut nodes_0_read, ChannelManagerReadArgs {
			default_config: test_default_channel_config(),
			keys_manager,
			fee_estimator: node_cfgs[0].fee_estimator,
			chain_monitor: nodes[0].chain_monitor,
			tx_broadcaster: nodes[0].tx_broadcaster.clone(),
			logger: nodes[0].logger,
			channel_monitors,
		}).unwrap()
	};
	nodes_0_deserialized = nodes_0_deserialized_tmp;
	assert!(nodes_0_read.is_empty());

	assert!(nodes[0].chain_monitor.watch_channel(chan_0_monitor.get_funding_txo().0, chan_0_monitor).is_ok());
	nodes[0].node = &nodes_0_deserialized;
	check_added_monitors!(nodes[0], 1);

	// On reload, the ChannelManager should realize it is stale compared to the ChannelMonitor and
	// force-close the channel.
	check_closed_event!(nodes[0], 1, ClosureReason::OutdatedChannelManager);
	assert!(nodes[0].node.list_channels().is_empty());
	assert!(nodes[0].node.has_pending_payments());
	let as_broadcasted_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(as_broadcasted_txn.len(), 1);
	assert_eq!(as_broadcasted_txn[0], as_commitment_tx);

	nodes[1].node.peer_disconnected(&nodes[0].node.get_our_node_id(), false);
	nodes[0].node.peer_connected(&nodes[1].node.get_our_node_id(), &msgs::Init { features: InitFeatures::known()});
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());

	// Now nodes[1] should send a channel reestablish, which nodes[0] will respond to with an
	// error, as the channel has hit the chain.
	nodes[1].node.peer_connected(&nodes[0].node.get_our_node_id(), &msgs::Init { features: InitFeatures::known()});
	let bs_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_channel_reestablish(&nodes[1].node.get_our_node_id(), &bs_reestablish);
	let as_err = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(as_err.len(), 1);
	match as_err[0] {
		MessageSendEvent::HandleError { node_id, action: msgs::ErrorAction::SendErrorMessage { ref msg } } => {
			assert_eq!(node_id, nodes[1].node.get_our_node_id());
			nodes[1].node.handle_error(&nodes[0].node.get_our_node_id(), msg);
			check_closed_event!(nodes[1], 1, ClosureReason::CounterpartyForceClosed { peer_msg: "Failed to find corresponding channel".to_string() });
			check_added_monitors!(nodes[1], 1);
			assert_eq!(nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0).len(), 1);
		},
		_ => panic!("Unexpected event"),
	}
	check_closed_broadcast!(nodes[1], false);

	// Now claim the first payment, which should allow nodes[1] to claim the payment on-chain when
	// we close in a moment.
	nodes[2].node.claim_funds(payment_preimage_1);
	check_added_monitors!(nodes[2], 1);
	let htlc_fulfill_updates = get_htlc_update_msgs!(nodes[2], nodes[1].node.get_our_node_id());
	nodes[1].node.handle_update_fulfill_htlc(&nodes[2].node.get_our_node_id(), &htlc_fulfill_updates.update_fulfill_htlcs[0]);
	check_added_monitors!(nodes[1], 1);
	commitment_signed_dance!(nodes[1], nodes[2], htlc_fulfill_updates.commitment_signed, false);

	if confirm_before_reload {
		let best_block = nodes[0].blocks.lock().unwrap().last().unwrap().clone();
		nodes[0].node.best_block_updated(&best_block.0, best_block.1);
	}

	// Create a new channel on which to retry the payment before we fail the payment via the
	// HTLC-Timeout transaction. This avoids ChannelManager timing out the payment due to us
	// connecting several blocks while creating the channel (implying time has passed).
	create_announced_chan_between_nodes(&nodes, 0, 1, InitFeatures::known(), InitFeatures::known());
	assert_eq!(nodes[0].node.list_usable_channels().len(), 1);

	mine_transaction(&nodes[1], &as_commitment_tx);
	let bs_htlc_claim_txn = nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	assert_eq!(bs_htlc_claim_txn.len(), 1);
	check_spends!(bs_htlc_claim_txn[0], as_commitment_tx);
	expect_payment_forwarded!(nodes[1], None, false);

	mine_transaction(&nodes[0], &as_commitment_tx);
	mine_transaction(&nodes[0], &bs_htlc_claim_txn[0]);
	expect_payment_sent!(nodes[0], payment_preimage_1);
	connect_blocks(&nodes[0], TEST_FINAL_CLTV*4 + 20);
	let as_htlc_timeout_txn = nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().split_off(0);
	check_spends!(as_htlc_timeout_txn[2], funding_tx);
	check_spends!(as_htlc_timeout_txn[0], as_commitment_tx);
	check_spends!(as_htlc_timeout_txn[1], as_commitment_tx);
	assert_eq!(as_htlc_timeout_txn.len(), 3);
	if as_htlc_timeout_txn[0].input[0].previous_output == bs_htlc_claim_txn[0].input[0].previous_output {
		confirm_transaction(&nodes[0], &as_htlc_timeout_txn[1]);
	} else {
		confirm_transaction(&nodes[0], &as_htlc_timeout_txn[0]);
	}
	nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
	expect_payment_failed!(nodes[0], payment_hash, false);

	// Finally, retry the payment (which was reloaded from the ChannelMonitor when nodes[0] was
	// reloaded) via a route over the new channel, which work without issue and eventually be
	// received and claimed at the recipient just like any other payment.
	let (new_route, _, _, _) = get_route_and_payment_hash!(nodes[0], nodes[2], 1_000_000);

	assert!(nodes[0].node.retry_payment(&new_route, payment_id_1).is_err()); // Shouldn't be allowed to retry a fulfilled payment
	nodes[0].node.retry_payment(&new_route, payment_id).unwrap();
	check_added_monitors!(nodes[0], 1);
	let mut events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	pass_along_path(&nodes[0], &[&nodes[1], &nodes[2]], 1_000_000, payment_hash, Some(payment_secret), events.pop().unwrap(), true, None);
	claim_payment_along_route(&nodes[0], &[&[&nodes[1], &nodes[2]]], false, payment_preimage);
}

#[test]
fn retry_with_no_persist() {
	do_retry_with_no_persist(true);
	do_retry_with_no_persist(false);
}
