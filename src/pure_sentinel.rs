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

//! PureSentinel cryptographically confirms the origin of a claim in a decentralised network.
//!
//! A claim has to implement Claimable in order to be verifiable and mergeable.
//! A request has to implement GetSigningKeys such that PureSentinel can aqcuire
//! the necessary public signing keys.
//! The request is passed immutably through pure sentinel
//! and is used as a key to group claims and corresponding keys.
//! When pure sentinel resolves a threshold on verified and merged message,
//! it returns the requestor key and the merged claim.
//! Claimant names and associated signatures are discarded after succesful resolution,
//! as such abstracting the original request into a resolved claim.
//!
//! The keys_threshold specifies a minimal threshold on the number of independent mentions of
//! a single public signing key needed to consider it for verifying a claim.  This threshold
//! can be one or higher.
//! The claims_threshold specifies a minimal threshold on the number of verified claims before
//! pure sentinel will attempt to merge these verified claims.

use super::{SerialisedClaim};

use sodiumoxide::crypto::sign::PublicKey;
use sodiumoxide::crypto::sign::Signature;
use accumulator::Accumulator;
use key_store::KeyStore;
use statistics::Frequency;

pub trait Source<Name> where Name: Eq + PartialOrd + Ord  + Clone {
    fn get_source(&self) -> Name;
}

pub enum AddResult<Request, Name> where Request: Eq + PartialOrd + Ord + Clone + Source<Name>,
                                        Name: Eq + PartialOrd + Ord + Clone {
    RequestKeys(Name),
    Resolved(Request, SerialisedClaim),
}

/// PureSentinel is templated on an immutable Request type, a mergeable Claim type.
/// It further takes a Name type to identify claimants.
/// Signature and PublicSignKey type are auxiliary types to handle a user-chosen
/// cryptographic signing scheme.
pub struct PureSentinel<Request, Name> where Request: Eq + PartialOrd + Ord + Clone + Source<Name>,
                                         Name: Eq + PartialOrd + Ord + Clone {
    claim_accumulator: Accumulator<Request, (Name, Signature, SerialisedClaim)>,
    key_store: KeyStore<Name>,
}

impl<Request, Name>
    PureSentinel<Request, Name>
    where Request: Eq + PartialOrd + Ord + Clone + Source<Name>,
          Name: Eq + PartialOrd + Ord + Clone {
    /// This creates a new pure sentinel that will collect a minimal claim_threshold number
    /// of verified claims before attempting to merge these claims.
    /// To obtain a verified claim PureSentinel needs to have received a matching public
    /// signing key. Each such a public signing key needs keys_threshold confirmations
    /// for it to be considered valid and used for verifying the signature
    /// of the corresponding claim.
    pub fn new()
        -> PureSentinel<Request, Name> {
        PureSentinel {
            claim_accumulator: Accumulator::new(0),
            key_store: KeyStore::new(),
        }
    }

    /// This adds a new claim for the provided request. The claimant name and
    /// the signature provided will be used to verify the claim with the keys
    /// that are independently retrieved. When an added claim leads to the
    /// resolution of the request, the request and the claim are returned.
    /// All resolved claims have to be identical. Otherwise None is returned.
    ///
    /// Possible results are:
    /// * Some(AddResult::Resolved(request, serialised_claim)): indicating
    ///   that the claim has been successfully resolved.
    /// * Some(AddResult::RequestKeys(target)): indicating that the caller
    ///   should request public keys from the group surrounding the target.
    /// * None: indicating that no resolve was possible yet.
    pub fn add_claim(&mut self,
                     request   : Request,
                     claimant  : Name,            // Node which sent the message
                     signature : Signature,
                     claim     : SerialisedClaim,
                     quorum_size: usize) -> Option<AddResult<Request, Name>> {

        let saw_first_time = !self.claim_accumulator.contains_key(&request);
        self.claim_accumulator.set_quorum_size(quorum_size);

        self.claim_accumulator
            .add(request.clone(), (claimant, signature, claim))
            .and_then(|(request, claims)| self.resolve(request, claims, quorum_size))
            .map(|(request, serialised_claim)| {
                AddResult::Resolved(request, serialised_claim)
            }).or_else(|| {
                if saw_first_time {
                    Some(AddResult::RequestKeys(request.get_source()))
                } else {
                    None
                }
            })
    }

    /// This adds a new set of public_signing_keys for the provided request.
    /// If the request is not known yet by pure sentinel, the added keys will be ignored.
    /// When the added set of keys leads to the resolution of the request,
    /// the request and the verified and merged claim is returned.
    /// Otherwise None is returned.
    pub fn add_keys(&mut self, request : Request, sender: Name, keys : Vec<(Name, PublicKey)>,
                    quorum_size: usize)
        -> Option<(Request, SerialisedClaim)> {
        // We don't want to store keys for requests we haven't received yet because
        // we couldn't have requested those keys. So someone is probably trying
        // something silly.
        if !self.claim_accumulator.contains_key(&request) {
            return None;
        }

        for (target, public_key) in keys {
            self.key_store.add_key(target, sender.clone(), public_key);
        }

        self.claim_accumulator.get(&request)
            .and_then(|(request, claims)| { self.resolve(request, claims, quorum_size) })
    }

    /// Verify is only concerned with checking the signatures of the serialised claims.
    /// To achieve this it pairs up a set of signed claims and a set of public signing keys.
    fn verify(&mut self, claims : &Vec<(Name, Signature, SerialisedClaim)>, quorum_size: usize)
        -> Vec<SerialisedClaim> {
        claims.iter().filter_map(|&(ref name, ref signature, ref body)| {
                self.verify_single_claim(name, signature, body, quorum_size)
            }).collect()
    }

    fn verify_single_claim(&mut self, name: &Name, signature: &Signature, body: &SerialisedClaim,
                           quorum_size: usize) -> Option<SerialisedClaim> {
        for public_key in self.key_store.get_accumulated_keys(&name, quorum_size) {
            match super::verify_signature(&signature, &public_key, &body) {
                Some(body) => return Some(body),
                None => continue
            }
        }
        None
    }

    fn squash(&self, verified_claims : Vec<SerialisedClaim>, quorum_size: usize)
        -> Option<SerialisedClaim> {
        if verified_claims.len() < quorum_size {
            // Can't squash: not enough claims.
            return None;
        }

        let mut frequency = Frequency::new();

        for verified_claim in verified_claims {
            frequency.update(&verified_claim)
        }

        let mut iter = frequency.sort_by_highest().into_iter()
            .filter(|&(_, ref count)| *count >= quorum_size)
            .map(|(resolved_claim, _)| resolved_claim);

        let retval = iter.next().map(|a| a.clone());

        // In debug mode we expect no adversaries.
        debug_assert!(retval.is_some(),      "Frequency returned less than one result");
        debug_assert!(iter.next().is_none(), "Frequency returned more than one result");

        retval
    }

    fn resolve(&mut self, request: Request, claims: Vec<(Name, Signature, SerialisedClaim)>,
               quorum_size: usize)
        -> Option<(Request, SerialisedClaim)> {
        let verified_claims = self.verify(&claims, quorum_size);
        self.squash(verified_claims, quorum_size)
            .map(|c| {
                self.claim_accumulator.delete(&request);
                (request, c)
            })
    }
}

#[cfg(test)]
mod test {

    extern crate rustc_serialize;
    use super::*;

    use rand::random;
    use sodiumoxide::crypto;
    use SerialisedClaim;

    const NAMESIZE: usize = 64;
    const QUORUM: usize = 10;

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
    pub struct TestName {
        pub data: Vec<u8>
    }

    fn generate_random_name() -> TestName {
        let mut arr = [0u8;NAMESIZE];
        for i in (0..NAMESIZE) { arr[i] = random::<u8>(); }
        TestName { data : arr.to_vec() }
    }

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
    struct TestRequest {
        core : usize,
        name : TestName
    }

    impl TestRequest {
        pub fn new(core: usize, name: TestName) -> TestRequest {
            TestRequest { core : core, name : name }
        }
    }

    impl Source<TestName> for TestRequest {
        fn get_source(&self) -> TestName {
            self.name.clone()
        }
    }

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
    struct TestClaim {
        value : usize
    }

    impl TestClaim {
        pub fn serialise(&self) -> SerialisedClaim {
            self.value.to_string().into_bytes()
        }
    }

#[test]
    fn one_request_and_one_key() {
        let quorum_size = 1usize;
        let mut name_key_pairs = Vec::new();
        let mut pure_sentinel: PureSentinel<TestRequest, TestName> = PureSentinel::new();
        let name = generate_random_name();
        let request = TestRequest::new(random::<usize>(), name.clone());
        let claim = TestClaim { value : random::<usize>() };
        let serialised_claim = claim.serialise();
        let key_pair = crypto::sign::gen_keypair();
        let signature = crypto::sign::sign_detached(&serialised_claim, &key_pair.1);
        let climant_name = generate_random_name();
        name_key_pairs.push((climant_name.clone(), key_pair.0.clone()));

        // first claim added should return AddResult::RequestKeys
        assert!(pure_sentinel.add_claim(request.clone(), climant_name.clone(), signature.clone(),
                                        serialised_claim.clone(), quorum_size)
            .and_then(|result| match result {
                AddResult::RequestKeys(source_name) => { assert_eq!(request.get_source(), source_name);
                                                         Some(source_name)
                                                       }
                AddResult::Resolved(_, _) => None
            }).is_some());

        // One key is required should pass
        assert!(pure_sentinel.add_keys(request.clone(), generate_random_name(), name_key_pairs.clone(),
                                       quorum_size)
            .and_then(|result| { assert_eq!(result.1, serialised_claim);
                                 assert_eq!(result.0, request);
                                 Some(result)
                               }).is_some());
    }

#[test]
    fn request_and_its_duplicate_added() {
        let mut pure_sentinel: PureSentinel<TestRequest, TestName> = PureSentinel::new();
        let name = generate_random_name();
        let request = TestRequest::new(random::<usize>(), name.clone());
        let claim = TestClaim { value : random::<usize>() };
        let serialised_claim = claim.serialise();
        let key_pair = crypto::sign::gen_keypair();
        let signature = crypto::sign::sign_detached(&serialised_claim, &key_pair.1);
        let climant_name = generate_random_name();

        // first claim added should return AddResult::RequestKeys
        assert!(pure_sentinel.add_claim(request.clone(), climant_name.clone(), signature.clone(),
                                        serialised_claim.clone(), QUORUM)
            .and_then(|result| match result {
                AddResult::RequestKeys(source_name) => {
                     assert_eq!(request.get_source(), source_name); Some(source_name) },
                AddResult::Resolved(_, _) => None
            }).is_some());

        // same claim added for the second time none to be returned
        assert!(pure_sentinel.add_claim(request, climant_name, signature, serialised_claim,
                                        QUORUM).is_none())
    }

#[test]
    fn threshold_claims_requests_added_with_no_keys() {
        let mut name_key_pairs = Vec::new();
        let mut pure_sentinel: PureSentinel<TestRequest, TestName> = PureSentinel::new();
        let name = generate_random_name();
        let request = TestRequest::new(random::<usize>(), name.clone());
        let claim = TestClaim { value : random::<usize>() };
        let serialised_claim = claim.serialise();
        for index in 0..QUORUM {
            let key_pair = crypto::sign::gen_keypair();
            let signature = crypto::sign::sign_detached(&serialised_claim, &key_pair.1);
            let climant_name = generate_random_name();
            name_key_pairs.push((climant_name.clone(), key_pair.0.clone()));
            assert!(pure_sentinel.add_claim(request.clone(), climant_name, signature.clone(),
                                            serialised_claim.clone(), QUORUM)
                .map_or(true, |result| match result {
                    AddResult::RequestKeys(source_name) => { assert_eq!(request.get_source(),
                                                                        source_name);
                                                             assert_eq!(index, 0usize);
                                                             true
                                                            },
                    AddResult::Resolved(_, _) => false
                }));
        }
    }

#[test]
    fn requests_added_with_various_key_size() {
        let mut name_key_pairs = Vec::new();
        let mut pure_sentinel: PureSentinel<TestRequest, TestName> = PureSentinel::new();
        let name = generate_random_name();
        let request = TestRequest::new(random::<usize>(), name.clone());
        let claim = TestClaim { value : random::<usize>() };
        let serialised_claim = claim.serialise();
        for index in 0..QUORUM {
            let key_pair = crypto::sign::gen_keypair();
            let signature = crypto::sign::sign_detached(&serialised_claim, &key_pair.1);
            let climant_name = generate_random_name();
            name_key_pairs.push((climant_name.clone(), key_pair.0.clone()));
            assert!(pure_sentinel.add_claim(request.clone(), climant_name, signature.clone(),
                                            serialised_claim.clone(), QUORUM)
                .map_or(true, |result| match result {
                    AddResult::RequestKeys(source_name) => { assert_eq!(request.get_source(), source_name);
                                                             assert_eq!(index, 0usize);
                                                             true
                                                            },
                    AddResult::Resolved(_, _) => false
                }));
        }

        // less than KEY_THRESHOLDS kyes received, should return None as the vector has the senders
        for index in 0..QUORUM {
            assert!(pure_sentinel.add_keys(request.clone(), name_key_pairs[index].0.clone(),
                                           name_key_pairs.clone(), QUORUM).is_none());
        }

        // KEY_THRESHOLDS kyes received, should not return none
        assert!(pure_sentinel.add_keys(request.clone(), generate_random_name(),
                                       name_key_pairs.clone(), QUORUM)
            .and_then(|result| { assert_eq!(result.1, serialised_claim);
                                 assert_eq!(result.0, request);
                                 Some(result)
            }).is_some());

        // more than KEY_THRESHOLDS kyes received, should return None
        assert!(pure_sentinel.add_keys(request, generate_random_name(), name_key_pairs,
                                       QUORUM).is_none());
    }
}
