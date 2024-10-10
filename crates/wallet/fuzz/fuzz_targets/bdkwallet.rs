#![no_main]

use libfuzzer_sys::fuzz_target;

use bdk_wallet::{
    bitcoin::{self, hashes::Hash, psbt::PsbtSighashType},
    chain::{BlockId, ConfirmationBlockTime, TxUpdate},
    KeychainKind, SignOptions, TxOrdering, Update as WalletUpdate, Wallet,
};
use rusqlite::Connection;
use std::{
    cmp,
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
};

// TODO: use more complicated descriptors.
const EXTERNAL_DESC: &str = "tr(xprvA1NeLXFV4y3Q3uZERyTp54EyaiRG76DcN3gXzW5bQpjt1JSTnTpi6KS4na6JsZMriWAiVcbePA9RAfNXmrfnXVJj33FvHUFgNNErYPaZE4g/122/1'/0'/0/*)";
const INTERNAL_DESC: &str = "wpkh(xprv9y5m1SxNcjAY8DJPHqXM67ETRFwpjsacG9xGBiTBMj5A2KupsjuNJuFuFJAzoQJb7fjp3jz78TsmDmqpaTtCBzAKEuqE1NMC3Net5Ma2hY6/84'/1'/0'/1/*)";
const NETWORK: bitcoin::Network = bitcoin::Network::Bitcoin;

enum Action {
    Update,
    Persist,
    TxCreate,
}

impl Action {
    pub fn from_byte(byte: u8) -> Option<Self> {
        if byte == 0x00 {
            Some(Self::Update)
        } else if byte == 0x01 {
            Some(Self::Persist)
        } else if byte == 0x02 {
            Some(Self::TxCreate)
        } else {
            None
        }
    }
}

struct UniqueHash {
    data: [u8; 32],
}

impl UniqueHash {
    pub fn new() -> Self {
        Self { data: [0; 32] }
    }

    pub fn get(&mut self) -> [u8; 32] {
        for byte in self.data.iter_mut().rev() {
            if *byte < u8::MAX {
                *byte += 1;
                break;
            }
        }
        self.data
    }

    pub fn get_block_hash(&mut self) -> bitcoin::BlockHash {
        bitcoin::hash_types::BlockHash::from_byte_array(self.get())
    }

    pub fn get_txid(&mut self) -> bitcoin::Txid {
        bitcoin::hash_types::Txid::from_byte_array(self.get())
    }
}

macro_rules! next_or_return {
    ($iter:expr) => {
        match $iter.next() {
            Some(val) => val,
            None => return,
        }
    };
}

fn scale(byte: u8) -> u32 {
    (byte as u32) * 0x01000000
}

fn scale_u64(byte: u8) -> u64 {
    (byte as u64) * 0x0100000000000000
}

fuzz_target!(|data: &[u8]| {
    let mut data_iter = data.iter();
    let mut conn = Connection::open_in_memory().unwrap();
    let mut wallet = Wallet::create(EXTERNAL_DESC, INTERNAL_DESC)
        .network(NETWORK)
        .create_wallet(&mut conn)
        .unwrap();
    let mut unique_hash = UniqueHash::new();
    let mut unconfirmed_txids = VecDeque::new();

    // Exercise the Wallet logic based on the fuzzer's input.
    loop {
        let action = if let Some(a) = Action::from_byte(*next_or_return!(data_iter)) {
            a
        } else {
            return;
        };

        match action {
            Action::Update => {
                // Start with active indices.
                let mut last_active_indices = BTreeMap::new();
                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    let indices_count = *next_or_return!(data_iter) as u32;
                    let index_start = scale(*next_or_return!(data_iter));
                    last_active_indices
                        .extend((index_start..indices_count).map(|i| (KeychainKind::Internal, i)));
                }
                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    let indices_count = *next_or_return!(data_iter) as u32;
                    let index_start = scale(*next_or_return!(data_iter));
                    last_active_indices
                        .extend((index_start..indices_count).map(|i| (KeychainKind::External, i)));
                }

                // Now do the transaction graph update.
                // TODO: more edge cases, eg coinbase txs.
                let txs_count = *next_or_return!(data_iter) as usize;
                let mut txs = Vec::with_capacity(txs_count);
                for _ in 0..txs_count {
                    let version = scale(*next_or_return!(data_iter)) as i32;
                    let version = bitcoin::transaction::Version(version);
                    let lock_time = scale(*next_or_return!(data_iter));
                    let lock_time = bitcoin::absolute::LockTime::from_consensus(lock_time);
                    let txin_count = *next_or_return!(data_iter) as usize;
                    let mut input = Vec::with_capacity(txin_count);
                    for _ in 0..txin_count {
                        let previous_output = bitcoin::OutPoint::new(
                            unique_hash.get_txid(),
                            *next_or_return!(data_iter) as u32,
                        );
                        input.push(bitcoin::TxIn {
                            previous_output,
                            ..Default::default()
                        });
                    }
                    let txout_count = *next_or_return!(data_iter) as usize;
                    let mut output = Vec::with_capacity(txout_count);
                    for _ in 0..txout_count {
                        let script_pubkey = if next_or_return!(data_iter) & 0x01 == 0x01 {
                            wallet
                                .next_unused_address(KeychainKind::External)
                                .script_pubkey()
                        } else if next_or_return!(data_iter) & 0x01 == 0x01 {
                            wallet
                                .next_unused_address(KeychainKind::Internal)
                                .script_pubkey()
                        } else {
                            bitcoin::ScriptBuf::from_bytes(unique_hash.get().into())
                        };
                        let amount = *next_or_return!(data_iter) as u64 * 1_000;
                        let value = bitcoin::Amount::from_sat(amount);
                        output.push(bitcoin::TxOut {
                            value,
                            script_pubkey,
                        });
                    }
                    let tx = bitcoin::Transaction {
                        version,
                        lock_time,
                        input,
                        output,
                    };
                    unconfirmed_txids.push_back(tx.compute_txid());
                    txs.push(tx.into());
                }

                let txouts_count = *next_or_return!(data_iter) as usize;
                let mut txouts = BTreeMap::new();
                for _ in 0..txouts_count {
                    let outpoint = bitcoin::OutPoint::new(
                        unique_hash.get_txid(),
                        *next_or_return!(data_iter) as u32,
                    );
                    let amount = *next_or_return!(data_iter) as u64 * 1_000;
                    let value = bitcoin::Amount::from_sat(amount);
                    txouts.insert(
                        outpoint,
                        bitcoin::TxOut {
                            value,
                            script_pubkey: Default::default(),
                        },
                    );
                }

                let mut anchors = BTreeSet::new();
                while next_or_return!(data_iter) & 0x01 == 0x01 {
                    let height = scale(*next_or_return!(data_iter));
                    let hash = unique_hash.get_block_hash();
                    let block_id = BlockId { height, hash };
                    let confirmation_time = scale_u64(*next_or_return!(data_iter));
                    let anchor = ConfirmationBlockTime {
                        block_id,
                        confirmation_time,
                    };
                    // FIXME: inserting anchors for transactions not in the tx graph will fail the
                    // SQLite persistence.
                    //let txid = unconfirmed_txids
                    //.pop_front()
                    //.unwrap_or(unique_hash.get_txid());
                    if let Some(txid) = unconfirmed_txids.pop_front() {
                        anchors.insert((anchor, txid));
                    } else {
                        break;
                    }
                }

                let mut seen_ats = HashMap::new();
                while next_or_return!(data_iter) & 0x01 == 0x01 {
                    let time = cmp::min(scale_u64(*next_or_return!(data_iter)), i64::MAX as u64 - 1);
                    let txid = unconfirmed_txids
                        .pop_front()
                        .unwrap_or(unique_hash.get_txid());
                    seen_ats.insert(txid, time);
                }

                let tx_update = TxUpdate {
                    txs,
                    txouts,
                    anchors,
                    seen_ats,
                };

                // Finally, do the chain update.
                // TODO: sometimes generate invalid updates, reorgs, etc.
                let chain = if next_or_return!(data_iter) & 0x01 == 0x01 {
                    let mut tip = wallet.latest_checkpoint();
                    let tip_height = tip.height();
                    let blocks_count = *next_or_return!(data_iter) as u32;
                    for i in 1..blocks_count + 1 {
                        tip = tip
                            .push(BlockId {
                                height: tip_height + i,
                                hash: unique_hash.get_block_hash(),
                            })
                            .unwrap();
                    }
                    Some(tip)
                } else {
                    None
                };

                // The Wallet update should never fail as we only ever create a consistent chain.
                let update = WalletUpdate {
                    last_active_indices,
                    tx_update,
                    chain,
                };
                wallet.apply_update(update).unwrap();
            }
            // Assert the wallet roundtrips to persistence and check some invariants.
            Action::Persist => {
                let balance_before = wallet.balance();
                let next_indices_before = (
                    wallet.next_derivation_index(KeychainKind::Internal),
                    wallet.next_derivation_index(KeychainKind::External),
                );
                let tip_before = wallet.latest_checkpoint();

                //eprintln!("About to persist {:?}", wallet.staged());
                wallet
                    .persist(&mut conn)
                    .expect("We should always be able to persist.");
                let expected_genesis = bitcoin::BlockHash::from_slice(
                    bitcoin::blockdata::constants::ChainHash::BITCOIN.as_bytes(),
                )
                .unwrap();
                wallet = Wallet::load()
                    .descriptor(KeychainKind::Internal, Some(INTERNAL_DESC))
                    .descriptor(KeychainKind::External, Some(EXTERNAL_DESC))
                    .check_network(NETWORK)
                    .check_genesis_hash(expected_genesis)
                    .load_wallet(&mut conn)
                    .expect("We should always be able to load back from persistence.")
                    .expect("Must exist as it was persisted just now.");

                assert_eq!(wallet.balance(), balance_before);
                let next_indices_after = (
                    wallet.next_derivation_index(KeychainKind::Internal),
                    wallet.next_derivation_index(KeychainKind::External),
                );
                assert_eq!(next_indices_after, next_indices_before);
                assert_eq!(wallet.latest_checkpoint(), tip_before);
            }
            Action::TxCreate => {
                let utxo = wallet.list_unspent().next();
                let change_address = wallet.next_unused_address(KeychainKind::Internal);
                let receive_address = wallet.next_unused_address(KeychainKind::External);

                let mut tx_builder = if next_or_return!(data_iter) & 0x01 == 0x01 {
                    wallet.build_tx()
                } else {
                    // TODO: be smarter, don't always pick the first one, sometimes pick a
                    // canonical one.
                    let txid = wallet.tx_graph().full_txs().next().map(|tx| tx.txid);
                    if let Some(txid) = txid {
                        if let Ok(builder) = wallet.build_fee_bump(txid) {
                            builder
                        } else {
                            return;
                        }
                    } else {
                        return;
                    }
                };

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    let mut rate = *next_or_return!(data_iter) as u64;
                    if next_or_return!(data_iter) & 0x01 == 0x01 {
                        rate *= 1_000;
                    }
                    let rate = bitcoin::FeeRate::from_sat_per_vb(rate).expect("within range.");
                    tx_builder.fee_rate(rate);
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    // FIXME: this can't be * 100 as as i initially set it to be as rust-bitcoin
                    // panics internally on overflowing Amount additions.
                    let mut fee = *next_or_return!(data_iter) as u64;
                    if next_or_return!(data_iter) & 0x01 == 0x01 {
                        fee *= 1_000;
                    }
                    let fee = bitcoin::Amount::from_sat(fee);
                    tx_builder.fee_absolute(fee);
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    if let Some(ref utxo) = utxo {
                        tx_builder.add_utxo(utxo.outpoint).expect("known utxo.");
                    }
                }

                // TODO: add foreign utxo

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    tx_builder.manually_selected_only();
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    if let Some(ref utxo) = utxo {
                        tx_builder.add_unspendable(utxo.outpoint);
                    }
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    let sighash = PsbtSighashType::from_u32(*next_or_return!(data_iter) as u32);
                    tx_builder.sighash(sighash);
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    let ordering = if next_or_return!(data_iter) & 0x01 == 0x01 {
                        TxOrdering::Shuffle
                    } else {
                        TxOrdering::Untouched
                    };
                    tx_builder.ordering(ordering);
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    let lock_time = scale(*next_or_return!(data_iter));
                    let lock_time = bitcoin::absolute::LockTime::from_consensus(lock_time);
                    tx_builder.nlocktime(lock_time);
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    let version = scale(*next_or_return!(data_iter)) as i32;
                    tx_builder.version(version);
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    tx_builder.do_not_spend_change();
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    tx_builder.only_spend_change();
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    tx_builder.only_witness_utxo();
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    tx_builder.include_output_redeem_witness_script();
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    tx_builder.add_global_xpubs();
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    tx_builder.drain_wallet();
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    tx_builder.enable_rbf();
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    tx_builder.allow_dust(true);
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    let recipients_count = *next_or_return!(data_iter) as usize;
                    let mut recipients = Vec::with_capacity(recipients_count);

                    for _ in 0..recipients_count {
                        let spk = if next_or_return!(data_iter) & 0x01 == 0x01 {
                            let spk_size = (*next_or_return!(data_iter) >> 3) as usize + 1;
                            bitcoin::ScriptBuf::from_bytes(unique_hash.get()[..spk_size].into())
                        } else if next_or_return!(data_iter) & 0x01 == 0x01 {
                            change_address.script_pubkey()
                        } else {
                            receive_address.script_pubkey()
                        };
                        let amount = *next_or_return!(data_iter) as u64 * 1_000;
                        let amount = bitcoin::Amount::from_sat(amount);
                        recipients.push((spk, amount));
                    }

                    tx_builder.set_recipients(recipients);
                }

                // TODO: add data

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    let spk = if next_or_return!(data_iter) & 0x01 == 0x01 {
                        let spk_size = (*next_or_return!(data_iter) >> 3) as usize + 1;
                        bitcoin::ScriptBuf::from_bytes(unique_hash.get()[..spk_size].into())
                    } else if next_or_return!(data_iter) & 0x01 == 0x01 {
                        change_address.script_pubkey()
                    } else {
                        receive_address.script_pubkey()
                    };
                    tx_builder.drain_to(spk);
                }

                let mut psbt = if let Ok(tx) = tx_builder.finish() {
                    tx
                } else {
                    return;
                };
                let mut sign_options = SignOptions::default();

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    sign_options.trust_witness_utxo = true;
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    let height = scale(*next_or_return!(data_iter));
                    sign_options.assume_height = Some(height);
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    sign_options.allow_all_sighashes = true;
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    sign_options.try_finalize = false;
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    sign_options.tap_leaves_options = bdk_wallet::signer::TapLeavesOptions::None;
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    sign_options.sign_with_tap_internal_key = false;
                }

                if next_or_return!(data_iter) & 0x01 == 0x01 {
                    sign_options.allow_grinding = false;
                }

                if wallet.sign(&mut psbt, sign_options.clone()).is_err() {
                    return;
                }

                // If after all this we managed to create and fully sign a valid transaction, add
                // it to the wallet.
                if let Ok(finalized) = wallet.finalize_psbt(&mut psbt, sign_options) {
                    if finalized {
                        let tx = match psbt.extract_tx() {
                            Err(e) => {
                                assert!(matches!(
                                    e,
                                    bitcoin::psbt::ExtractTxError::AbsurdFeeRate { .. }
                                ));
                                return;
                            }
                            Ok(tx) => tx,
                        };
                        let mut wallet_update = WalletUpdate::default();
                        wallet_update.tx_update.txs.push(tx.into());
                        wallet.apply_update(wallet_update).unwrap();
                    }
                }
            }
        }
    }
});
