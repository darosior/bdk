#![no_main]

use bdk_chain::{
    bitcoin::{self, hashes::Hash},
    local_chain::{ChangeSet, LocalChain},
    CheckPoint,
};
use libfuzzer_sys::fuzz_target;
use std::{
    cmp,
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
};

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
}

macro_rules! next_or_return {
    ($iter:expr) => {
        match $iter.next() {
            Some(val) => val,
            None => return,
        }
    };
}

fn is_odd(n: &u8) -> bool {
    n & 0x01 == 0x01
}

fuzz_target!(|data: &[u8]| {
    let mut data = data.iter();
    let mut unique_hashes = UniqueHash::new();

    // First create an initial, valid, chain.
    // TODO: scale chain size to a few thousands.
    let initial_chain_len = cmp::max(1, *next_or_return!(data) as u32);
    let mut initial_blocks = BTreeMap::new();
    initial_blocks.insert(0, Some(unique_hashes.get_block_hash()));
    for i in 1..initial_chain_len - 1 {
        if is_odd(next_or_return!(data)) {
            initial_blocks.insert(
                i,
                is_odd(next_or_return!(data)).then_some(unique_hashes.get_block_hash()),
            );
        } else {
            let height = cmp::max(1, *next_or_return!(data) as u32);
            initial_blocks.insert(
                height,
                is_odd(next_or_return!(data)).then_some(unique_hashes.get_block_hash()),
            );
        }
    }
    let mut initial_chain = LocalChain::from_changeset(ChangeSet {
        blocks: initial_blocks.clone(),
    })
    .expect("A genesis block is always present.");
    let initial_chain_height = initial_chain.tip().height();

    // Now create another chain to be merged with the initial one. Sometimes extend the initial
    // chain, sometimes not, depending on the fuzzer's input.
    // TODO: sometimes add some hashes from the initial chain in the update chain.
    let mut connects = false;
    let mut reorg_height = None;
    let update_chain_len = cmp::max(2, *next_or_return!(data) as u32);
    let (mut height, mut update_cp) = if is_odd(next_or_return!(data)) {
        (
            cmp::max(1, *next_or_return!(data) as u32),
            CheckPoint::new((0, initial_chain.genesis_hash()).into()),
        )
    } else {
        connects = true;
        (
            initial_chain_height + 1,
            CheckPoint::new(initial_chain.tip().block_id()),
        )
    };
    for _ in 0..update_chain_len - 1 {
        height += if is_odd(next_or_return!(data)) {
            *next_or_return!(data) as u32
        } else {
            0
        };
        let hash = unique_hashes.get_block_hash();
        update_cp = update_cp
            .push((height, hash).into())
            .expect("Height is always increasing.");
        // BDK requires that the block right after the point of agreement in the initial chain be
        // included in the original chain for it to connect. We check if this block is this "first
        // block to conflict" by:
        // 1) Checking it is at all in the initial chain
        if !connects && initial_blocks.contains_key(&height) {
            // 2) Checking it does indeed conflict with the block in the initial chain.
            if let Some(Some(conflict_h)) = initial_blocks.get(&height) {
                if hash != *conflict_h {
                    // 3) Checking the block right before is the point of agreement.
                    if let Some(ref prev) = update_cp.prev() {
                        if let Some(Some(agree_h)) = initial_blocks.get(&prev.height()) {
                            if prev.hash() == *agree_h {
                                // 4) Checking the block right after the point of agreement in the
                                //    initial chain is indeed at the height of our conflict block.
                                if let Some((initial_agree_h, _)) =
                                    initial_blocks.range(prev.height() + 1..).next()
                                {
                                    if *initial_agree_h == height {
                                        //eprintln!("Connects");
                                        connects = true;
                                        reorg_height = Some(height);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        height += 1;
    }

    //dbg!(&initial_chain);
    //dbg!(&update_cp);
    let merge_res = initial_chain.apply_update(update_cp.clone());
    if connects {
        //dbg!(&merge_res);
        let merge_res = merge_res.expect("Must only fail if it cannot connect.");
        let new_chain_height = update_cp.height();
        // All blocks in the update but the very first must have been recorded as newly added, no
        // matter if it was extending or reorg'ing the chain.
        loop {
            if let Some(cp) = update_cp.prev() {
                let update_hash = merge_res
                    .blocks
                    .get(&update_cp.height())
                    .expect("Must contain all blocks from update.")
                    .expect("Must be an added block.");
                assert_eq!(update_cp.hash(), update_hash);
                update_cp = cp;
            } else {
                break;
            }
        }
        // If the update chain is smaller than the initial block, all blocks in the initial chain
        // whose height is higher than the update's tip must have been recorded as dropped.
        if new_chain_height < initial_chain_height {
            if let Some(_) = reorg_height {
                assert!(merge_res
                    .blocks
                    .range(new_chain_height + 1..)
                    .all(|entry| entry.1.is_none()));
            }
        }
    }
});
