// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use sodiumoxide::crypto::sign;
use lru_time_cache::LruCache;
use std::collections::{BTreeMap, BTreeSet};

const NAME_CAPACITY: usize = 1000;

// FIXME: We only work with KeyData and not PublicKey directly
// because PublicKey doesn't derive from Ord in the current version of
// sodiumdioxide library. Once that library is bumped to version 0.0.6
// or above, we should be able to get rid of KeyData and the re-wrapping.
type KeyData   = [u8; sign::PUBLICKEYBYTES];
type Map<A, B> = BTreeMap<A,B>;
type Set<A>    = BTreeSet<A>;

#[derive(Clone)]
pub struct KeyStore<Name>
    where Name: Eq + PartialOrd + Ord + Clone
{
    //              +--- Target            +--- Sender
    //              V                      V
    cache: LruCache<Name, Map<KeyData, Set<Name>>>,
}

impl<Name> KeyStore<Name> where Name: Eq + PartialOrd + Ord + Clone {
    pub fn new() -> KeyStore<Name> {
        KeyStore { cache: LruCache::with_capacity(NAME_CAPACITY) }
    }

    pub fn add_key(&mut self, target: Name, sender: Name, key: sign::PublicKey) {
        // No self signing.
        if target == sender {
            return;
        }

        let new_map = || Map::<KeyData, Set<Name>>::new();
        let new_set = || Set::<Name>::new();

        self.cache.entry(target).or_insert_with(new_map)
                  .entry(key.0).or_insert_with(new_set)
                  .insert(sender);
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns a vector of keys belonging to `target`, for whom we've received the key
    /// from at least a quorum size of unique senders.
    pub fn get_accumulated_keys(&mut self,
                                target: &Name,
                                quorum_size: usize)
                                -> Vec<sign::PublicKey> {
        // Create temp variable to workaround a borrow checker bug
        // http://blog.ezyang.com/2013/12/two-bugs-in-the-borrow-checker-every-rust-developer-should-know-about/
        self.cache.get(target)
            .iter().flat_map(|keys| Self::pick_where_quorum_reached(keys, quorum_size))
            .cloned().map(sign::PublicKey)
            .collect::<_>()
    }

    fn pick_where_quorum_reached<'a>(keys: &'a Map<KeyData, Set<Name>>,
                                     quorum: usize)
                                     -> Vec<&'a KeyData> {
        keys.iter().filter_map(|(key, sender_set)| {
            if sender_set.len() >= quorum { Some(key) } else { None }
        }).collect::<_>()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use sodiumoxide::crypto::sign;
    use rand::random;

    type NameType = u8;
    const QUORUM: usize = 6;

    fn random_key() -> sign::PublicKey {
        let mut arr = [0u8;sign::PUBLICKEYBYTES];
        for i in 0..sign::PUBLICKEYBYTES {
            arr[i] = random::<u8>();
        }
        sign::PublicKey(arr)
    }

    fn add_noise(ks: &mut KeyStore<NameType>, target: NameType, quantity: usize) {
        for _ in 0..quantity {
            ks.add_key(target, random::<NameType>(), random_key());
        }
    }

    #[test]
    fn quorum_reached() {
        let target: NameType = 0;
        let mut ks = KeyStore::<NameType>::new();
        let valid_key = random_key();

        add_noise(&mut ks, target, 1000);

        for i in 1..QUORUM + 1 {
            ks.add_key(target, i as NameType, valid_key);

            if i < QUORUM {
                assert!(ks.get_accumulated_keys(&target, QUORUM).is_empty());
            } else {
                assert!(!ks.get_accumulated_keys(&target, QUORUM).is_empty());
            }
        }
    }

    #[test]
    fn no_self_sign() {
        let target: NameType = 0;
        let mut ks = KeyStore::<NameType>::new();
        let valid_key = random_key();

        add_noise(&mut ks, target, 1000);

        // Node zero sends signature for zero, that shouldn't be valid.
        for i in 0..QUORUM {
            ks.add_key(target, i as NameType, valid_key);
            assert!(ks.get_accumulated_keys(&target, QUORUM).is_empty());
        }
    }

    #[test]
    fn successful_attack() {
        let target: NameType = 0;
        let mut ks = KeyStore::<NameType>::new();
        let valid_key1 = random_key();
        let valid_key2 = random_key();

        add_noise(&mut ks, target, 1000);

        for i in 1..QUORUM + 1 {
            ks.add_key(target, i as NameType, valid_key1);

            if i < QUORUM {
                assert!(ks.get_accumulated_keys(&target, QUORUM).len() == 0);
            } else {
                assert!(ks.get_accumulated_keys(&target, QUORUM).len() == 1);
            }
        }

        for i in 1..QUORUM + 1 {
            ks.add_key(target, i as NameType, valid_key2);

            if i < QUORUM {
                assert!(ks.get_accumulated_keys(&target, QUORUM).len() == 1);
            } else {
                assert!(ks.get_accumulated_keys(&target, QUORUM).len() == 2);
            }
        }
    }

}
