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

extern crate sodiumoxide;
extern crate cbor;
extern crate accumulator;
extern crate rustc_serialize;

mod frequency;

use std::collections::HashMap;
use sodiumoxide::crypto;
use accumulator::Accumulator;
use frequency::Frequency;
use rustc_serialize::{Decodable, Encodable};


pub trait Mergeable {
  fn merge<'a, I>(i: I) -> Option<Self> where I: Iterator<Item=&'a Self>;
}

pub trait Validatable {
  fn validate<'a, I, J>(i: I, j: J) -> Option<Self>
      where I: Iterator<Item=&'a Self>, J: Iterator<Item=&'a Self>;
}

pub trait GetCredentials<K>
    where K: Eq + PartialOrd + Ord + Clone {
  fn get(&mut self, key: K);
}

/// K = key
/// V = value
/// C = credentials

pub struct Sentinel<'a, K, V, C>
    where K: Eq + PartialOrd + Ord + Clone,
          V: Eq + Mergeable + Validatable + Clone,
          C: Mergeable + Clone {

  get_credentials: &'a mut (GetCredentials + 'a),
  group_size: usize,
  value_accumulator: Accumulator<K, V>,
  credential_accumulator: Accumulator<K, C>,
}

impl<'a, K, V, C> Sentinel<'a, K, V, C>
        where K: PartialOrd + Ord + Clone,
              V: Mergeable + Validatable + Clone,
              C: Mergeable + Clone {

  pub fn new(get_credentials: &'a mut GetCredentials, group_size: usize, quorum_size: usize)
      -> Sentinel<'a, K, V, C> {

    Sentinel {
      get_credentials: get_credentials,
      group_size: group_size,
      value_accumulator: Accumulator::<K,V>::new(quorum_size),
      credentials_accumulator: Accumulator::<K,C>::new(quorum_size)
    }
  }

  pub fn add_value(&mut self, key: K, value: V) -> Option<(K, V)> {   
    if !self.value_accumulator.has_key(&key) {
      self.get_credentials.get(key.clone());
    }

    let values = self.value_accumulator.add(key.clone(), value.clone());
 
    if values.is_some() {
      let credentials = self.credentials_accumulator.get(&key);
      if credentials.is_some() {
        let resolved = Sentinel::resolve(Sentinel::validate(
                values.unwrap().1, credentials.unwrap().1));

        if resolved.is_some() {
          self.value_accumulator.delete(&key);
          self.credentials_accumulator.delete(&key);
          return resolved;
        }
      }
    }

    None
  }

  pub fn add_credentials(&mut self, key: K, credentials: C) -> Option<(K, V)> {
    let credentials = self.credentials_accumulator.add(key, credentials);

    if credentials.is_some() {
      let values = self.value_accumulator.get(&key);
      if values.is_some() {
        let resolved = Sentinel::resolve(Sentinel::validate(
                values.unwrap().1, credentials.unwrap().1));

        if resolved.is_some() {
          self.value_accumulator.delete(&key);
          self.credentials_accumulator.delete(&key);
          return resolved;
        }
      }
    }

    None
  }

    // fn check_signature(response: &ResultType, pub_key: &PublicSignKey) -> Option<ResultType> {
    //     let is_correct = crypto::sign::verify_detached(
    //                        &response.3.get_crypto_signature(),
    //                        &response.2[..],
    //                        &pub_key.get_crypto_public_sign_key());

    //     if !is_correct { return None; }
    //     Some(response.clone())
    // }

    fn validate(values: Vec<V>, credentials: Vec<C>) -> Vec<(ResultType)> {
      // TODO: Would be nice if we didn't need to decode it here every time
      // this function is called. We could then avoid the below check as well.
      let credentials = credentials.iter()
                                   .filter_map(|c| Sentinel::decode(&c.2))
                                   .collect::<Vec<_>>();

      // Need to check this again because decoding may have failed.
      if credentials.len() < quorum_size {
          return Vec::<ResultType>::new();
      }

      let credential_map =
          Mergeable::merge(credentials.iter())
              .into_iter()
              .flat_map(|GetGroupKeyResponse{ public_sign_keys: addr_key_pairs }| {
                          addr_key_pairs.into_iter()
                        })
              .collect::<HashMap<_,_>>();

      values.iter()
            .filter_map(|value| {
                          credential_map.get(&value.0.from_node())
                          .and_then(|credential| Sentinel::check_signature(&value, &credential))
                        })
            .collect::<Vec<_>>()
    }

    // fn decode<T: Decodable>(data: &SerialisedMessage) -> Option<T> {
    //     let mut decoder = cbor::Decoder::from_bytes(data.clone());
    //     decoder.decode().next().and_then(|result_msg| result_msg.ok())
    // }

    // fn encode<T: Encodable>(value: T) -> SerialisedMessage {
    //     let mut e = cbor::Encoder::from_memory();
    //     let _ = e.encode(&[&value]); // FIXME: Panic when failed to encode?
    //     e.as_bytes().to_vec()
    // }

    // fn resolve(verified_messages : Vec<ResultType>) -> Option<ResultType> {
    //     if verified_messages.len() < quorum_size as usize {
    //         return None;
    //     }

    //     // TODO: Make sure the header is used from a message that belongs to the quorum.

    //     return if verified_messages[0].1 == MessageTypeTag::FindGroupResponse {
    //         let decoded_responses = verified_messages.iter()
    //             .filter_map(|msg| Sentinel::decode::<FindGroupResponse>(&msg.2))
    //             .collect::<Vec<_>>();

    //         //FIXME(ben): after merging the messages the headers and the signature
    //         //            have lost meaning; we should be returning less then this;
    //         //            in particular will the signature no longer match
    //         //            merged message
    //         Mergeable::merge(decoded_responses.iter()).map(|merged| {
    //             (verified_messages[0].0.clone(),
    //              verified_messages[0].1.clone(),
    //              Sentinel::encode(merged),
    //              verified_messages[0].3.clone())
    //         })
    //     } else if verified_messages[0].1 == MessageTypeTag::GetGroupKeyResponse {
    //         // TODO: GetGroupKeyResponse will probably never reach this function.(?)
    //         let accounts = verified_messages.iter()
    //             .filter_map(|msg_triple| { Sentinel::decode::<GetGroupKeyResponse>(&msg_triple.2) })
    //             .collect::<Vec<_>>();

    //         //FIXME(ben): see comment above
    //         Mergeable::merge(accounts.iter()).map(|merged| {
    //             (verified_messages[0].0.clone(),
    //              verified_messages[0].1.clone(),
    //              Sentinel::encode(merged),
    //              verified_messages[0].3.clone())
    //         })
    //     } else {
    //         let header = verified_messages[0].0.clone();
    //         let tag    = verified_messages[0].1.clone();
    //         //FIXME(ben): see comment above
    //         let signature = verified_messages[0].3.clone();

    //         let msg_bodies = verified_messages.into_iter()
    //                          .map(|(_, _, body, _)| body)
    //                          .collect::<Vec<_>>();

    //         take_most_frequent(&msg_bodies, quorum_size as usize)
    //             .map(|merged| { (header, tag, merged, signature) })
    //     }
    // }
}

fn take_most_frequent<E>(elements: &Vec<E>, min_count: usize) -> Option<E>
where E: Clone + Ord {
    let mut freq_counter = Frequency::<E>::new();
    for element in elements {
        freq_counter.update(element.clone());
    }
    freq_counter.sort_by_highest().into_iter().nth(0).and_then(|(element, count)| {
        if count >= min_count as usize { Some(element) } else { None }
    })
}

#[cfg(test)]
mod test {

  use super::*;
  // use std::cmp;
  // use sodiumoxide::crypto;
  // use types;
  // use name_type::closer_to_target;
  // use NameType;
  // use message_header;
  // use messages;
  // use rustc_serialize::{Encodable, Decodable};
  // use rand;
  // use cbor;
  // use test_utils::Random;
  // use message_header::MessageHeader;
  // use messages::{RoutingMessage, MessageTypeTag};
  // use messages::put_data::PutData;
  // use messages::get_group_key_response::GetGroupKeyResponse;
  // use types::{MessageId, Pmid, PublicPmid, GroupAddress, NodeAddress, DestinationAddress,
  //             SourceAddress, Authority, PublicSignKey, GROUP_SIZE, vector_as_u8_64_array};
  // use sodiumoxide::crypto::hash::sha512::hash;
  // use rand::{thread_rng, Rng};
  // use rand::distributions::{IndependentSample, Range};

  #[test]
    fn it_works() {
  }


  // SentinelMessages

  // pub struct SentinelMessages {
  //   pmids: Vec<Pmid>,
  //   extras: Vec<Pmid>,
  //   random: Pmid,
  //   group_keys: Vec<Vec<PublicPmid>>,
  //   client_keys: Vec<PublicPmid>
  // }

  // impl SentinelMessages {
  //   pub fn new(size: usize)-> SentinelMessages {
  //     assert!(size >= GROUP_SIZE as usize);
  //     let mut pmids = Vec::new();
  //     for _ in 0..size {
  //       pmids.push(Pmid::new());
  //     }
  //     let mut extras = Vec::new();
  //     for _ in 1..GROUP_SIZE as usize {
  //       extras.push(Pmid::new());
  //     }

  //     SentinelMessages {
  //       pmids: pmids,
  //       extras: extras,
  //       random: Pmid::new(),
  //       group_keys: Vec::new(),
  //       client_keys: Vec::new()
  //     }
  //   }

  //   fn sort_pmids(&mut self, target: GroupAddress) {
  //     self.pmids.sort_by(
  //         |a, b| if closer_to_target(&a.get_name(), &b.get_name(), &target) {
  //                   cmp::Ordering::Less
  //                } else {
  //                   cmp::Ordering::Greater
  //                });
  //   }

  //   fn get_pmids(&self, size: usize) -> Vec<Pmid> {
  //     assert!(self.pmids.len() >= size);
  //     let mut result = Vec::new();
  //     for i in 0..size {
  //       result.push(self.pmids[i].clone());
  //     }
  //     result
  //   }

  //   fn get_sorted_pmids(&mut self, target: GroupAddress, size: usize) -> Vec<Pmid> {
  //     self.sort_pmids(target);
  //     self.get_pmids(size)
  //   }

  //   pub fn group_messages<T>(&mut self, request: T,
  //                                       tag: MessageTypeTag,
  //                                       message_id: MessageId,
  //                                       authority: Authority,
  //                                       destination: GroupAddress,
  //                                       source: GroupAddress) -> Vec<RoutingMessage>
  //         where T: Encodable + Decodable + Clone {
  //     let group_size = GROUP_SIZE as usize;
  //     self.sort_pmids(source.clone());

  //     let mut messages = Vec::new();

  //     for i in 0..group_size {
  //       let destination = DestinationAddress{ dest: destination.clone(), reply_to: None };
  //       let node = self.pmids[i].get_name().clone();
  //       let group = source.clone();
  //       let source = SourceAddress{ from_node: node, from_group: Some(group), reply_to: None };
  //       let header = MessageHeader::new(message_id, destination, source, authority.clone());
  //       let sign_key = self.pmids[i].get_crypto_secret_sign_key();

  //       messages.push(RoutingMessage::new(tag.clone(), header, request.clone(), &sign_key));
  //     }

  //     messages
  //   }

  //   pub fn fake_messages<T>(&mut self, request: T,
  //                                      tag: MessageTypeTag,
  //                                      message_id: MessageId,
  //                                      authority: Authority,
  //                                      destination: GroupAddress,
  //                                      source: GroupAddress) -> Vec<RoutingMessage>
  //         where T: Encodable + Decodable + Clone {
  //     let group_size = GROUP_SIZE as usize;
  //     self.sort_pmids(source.clone());

  //     let mut messages = Vec::new();

  //     let mut rng = thread_rng();
  //     let range = Range::new(0, group_size);
  //     {
  //       // choose random Pmid from first GROUP_SIZE sorted Pmids...
  //       let index = range.ind_sample(&mut rng);

  //       let destination = DestinationAddress{ dest: destination.clone(), reply_to: None };
  //       let node = self.pmids[index].get_name().clone();
  //       let group = source.clone();
  //       let source = SourceAddress{ from_node: node, from_group: Some(group), reply_to: None };
  //       let header = MessageHeader::new(message_id, destination, source, authority.clone());
  //       let sign_key = self.pmids[index].get_crypto_secret_sign_key();

  //       self.random = self.pmids[index].clone();  // ...set 'random' to chosen Pmid

  //       messages.push(RoutingMessage::new(tag.clone(), header, request.clone(), &sign_key));
  //     }
  //     // use 'extras' for remaining messages...
  //     for i in 0..group_size - 1 {
  //       let destination = DestinationAddress{ dest: destination.clone(), reply_to: None };
  //       let node = self.extras[i].get_name().clone();
  //       let group = source.clone();
  //       let source = SourceAddress{ from_node: node, from_group: Some(group), reply_to: None };
  //       let header = MessageHeader::new(message_id, destination, source, authority.clone());
  //       let sign_key = self.extras[i].get_crypto_secret_sign_key();

  //       messages.push(RoutingMessage::new(tag.clone(), header, request.clone(), &sign_key));
  //     }

  //     messages
  //   }

  //   pub fn group_key_responses(&mut self, message_id: MessageId,
  //                                         authority: Authority,
  //                                         destination: GroupAddress,
  //                                         source: GroupAddress) -> Vec<RoutingMessage> {
  //     let group_size = GROUP_SIZE as usize;
  //     assert!(self.pmids.len() >= group_size);
  //     let sorted = self.get_sorted_pmids(source.clone(), group_size);
  //     self.group_keys.clear();
  //     for i in 0..sorted.len() {
  //       let closest = self.get_sorted_pmids(sorted[i].get_name(), group_size);
  //       let mut public_pmids = Vec::new();
  //       for j in 0..closest.len() {
  //           public_pmids.push(PublicPmid::new(&closest[j]));
  //       }
  //       self.group_keys.push(public_pmids.clone());
  //     }

  //     let mut messages = Vec::new();

  //     for i in 0..group_size {
  //       let mut public_sign_keys = Vec::new();
  //       for j in 0..group_size {
  //         public_sign_keys.push((self.group_keys[i][j].name.clone(),
  //                                self.group_keys[i][j].public_sign_key.clone()));
  //       }

  //       let group_key_response = GetGroupKeyResponse{ public_sign_keys: public_sign_keys };
  //       let destination = DestinationAddress{ dest: destination.clone(), reply_to: None };
  //       let node = self.group_keys[i][0].name.clone();
  //       let group = source.clone();
  //       let source = SourceAddress{ from_node: node, from_group: Some(group), reply_to: None };
  //       let tag = MessageTypeTag::GetGroupKeyResponse;
  //       let header = MessageHeader::new(message_id, destination, source, authority.clone());
  //       let sign_key = self.pmids[i].get_crypto_secret_sign_key();

  //       messages.push(RoutingMessage::new(tag, header, group_key_response.clone(), &sign_key));
  //     }

  //     messages
  //   }

  //   pub fn fake_group_keys_responses(&mut self, message_id: MessageId,
  //                                               authority: Authority,
  //                                               destination: GroupAddress,
  //                                               source: GroupAddress) -> Vec<RoutingMessage> {
  //     let group_size = GROUP_SIZE as usize;
  //     assert!(self.pmids.len() >= group_size);
  //     let sorted = self.get_sorted_pmids(source.clone(), group_size);
  //     self.group_keys.clear();
  //     for i in 0..sorted.len() {
  //       let closest = self.get_sorted_pmids(sorted[i].get_name(), group_size);
  //       let mut public_pmids = Vec::new();
  //       for j in 0..closest.len() {
  //           public_pmids.push(PublicPmid::new(&closest[j]));
  //       }
  //       self.group_keys.push(public_pmids.clone());
  //     }

  //     // append 'extras' and 'random' PublicPmids' GROUP_SIZE times...
  //     for i in 0..group_size {
  //       let mut public_pmids = Vec::new();
  //       for j in 0..self.extras.len() {
  //           public_pmids.push(PublicPmid::new(&self.extras[j]));
  //       }
  //       public_pmids.push(PublicPmid::new(&self.random));
  //       self.group_keys.push(public_pmids.clone());
  //     }

  //     let mut messages = Vec::new();

  //     for i in 0..group_size {
  //       let mut public_sign_keys = Vec::new();
  //       for j in 0..group_size {
  //         public_sign_keys.push((self.group_keys[i][j].name.clone(),
  //                                self.group_keys[i][j].public_sign_key.clone()));
  //       }

  //       let group_key_response = GetGroupKeyResponse{ public_sign_keys: public_sign_keys };
  //       let destination = DestinationAddress{ dest: destination.clone(), reply_to: None };
  //       let node = self.group_keys[i][0].name.clone();
  //       let group = source.clone();
  //       let source = SourceAddress{ from_node: node, from_group: Some(group), reply_to: None };
  //       let tag = MessageTypeTag::GetGroupKeyResponse;
  //       let header = MessageHeader::new(message_id, destination, source, authority.clone());
  //       let sign_key = self.pmids[i].get_crypto_secret_sign_key();

  //       messages.push(RoutingMessage::new(tag, header, group_key_response.clone(), &sign_key));
  //     }

  //     let mut index: usize = 0;
  //     for i in group_size..2 * group_size - 1 {
  //       let mut public_sign_keys = Vec::new();
  //       for j in 0..group_size {
  //         public_sign_keys.push((self.group_keys[i][j].name.clone(),
  //                                self.group_keys[i][j].public_sign_key.clone()));
  //       }

  //       let group_key_response = GetGroupKeyResponse{ public_sign_keys: public_sign_keys };
  //       let destination = DestinationAddress{ dest: destination.clone(), reply_to: None };
  //       let node = self.group_keys[i][index].name.clone();
  //       let group = source.clone();
  //       let source = SourceAddress{ from_node: node, from_group: Some(group), reply_to: None };
  //       let tag = MessageTypeTag::GetGroupKeyResponse;
  //       let header = MessageHeader::new(message_id, destination, source, authority.clone());
  //       let sign_key = self.extras[index].get_crypto_secret_sign_key();

  //       index += 1usize;
  //       assert!(index < group_size); // ...don't include 'random' again
  //       messages.push(RoutingMessage::new(tag, header, group_key_response.clone(), &sign_key));
  //     }

  //     messages
  //   }

  // }

  // impl SendGetKeys for SentinelMessages {
  //   fn get_client_key(&mut self, node_address: NodeAddress) {}
  //   fn get_group_key(&mut self, group_address: GroupAddress) {}
  // }


  // #[test]
  // fn ordered_group_messages() {
  //   // network_size is the number of Pmid's created for test...
  //   let network_size = 1000usize;
  //   let mut sentinel_messages = SentinelMessages::new(network_size);
  //   let data = generate_data(64usize);
  //   let name = NameType::new(vector_as_u8_64_array(hash(&data[..]).0.to_vec()));
  //   let message_id = rand::random::<u32>() as types::MessageId;
  //   let destination = name.clone();
  //   let source = NameType::generate_random();
  //   let authority = Authority::ClientManager;
  //   let request = PutData{ name: name.clone(), data: data.clone() };
  //   let tag = MessageTypeTag::PutData;

  //   let group_messages =
  //       sentinel_messages.group_messages(
  //           request,
  //           tag,
  //           message_id,
  //           authority.clone(),
  //           destination.clone(),
  //           source.clone());

  //   let group_keys_responses =
  //       sentinel_messages.group_key_responses(
  //           message_id,
  //           authority.clone(),
  //           destination.clone(),
  //           source.clone());

  //   {
  //     let mut resolved = None;
  //     let mut sentinel = Sentinel::new(&mut sentinel_messages);

  //     for msg in group_messages {
  //       resolved =
  //           sentinel.add(
  //               msg.message_header,
  //               msg.message_type,
  //               msg.serialised_body,
  //               msg.signature);

  //       assert!(resolved.is_none());
  //     }
  //     for keys in group_keys_responses {
  //       resolved =
  //           sentinel.add(
  //               keys.message_header,
  //               keys.message_type,
  //               keys.serialised_body,
  //               keys.signature);

  //       if resolved.is_some() {
  //         break;
  //       }
  //     }

  //     assert!(resolved.is_some());
  //   }
  // }

  // #[test]
  // fn unordered_group_messages() {
  //   // network_size is the number of Pmid's created for test...
  //   let network_size = 1000usize;
  //   let mut sentinel_messages = SentinelMessages::new(network_size);
  //   let data = generate_data(64usize);
  //   let name = NameType::new(vector_as_u8_64_array(hash(&data[..]).0.to_vec()));
  //   let message_id = rand::random::<u32>() as types::MessageId;
  //   let destination = name.clone();
  //   let source = NameType::generate_random();
  //   let authority = Authority::ClientManager;
  //   let request = PutData{ name: name.clone(), data: data.clone() };
  //   let tag = MessageTypeTag::PutData;

  //   let mut group_messages =
  //       sentinel_messages.group_messages(
  //           request,
  //           tag,
  //           message_id,
  //           authority.clone(),
  //           destination.clone(),
  //           source.clone());

  //   let mut group_keys_responses =
  //       sentinel_messages.group_key_responses(
  //           message_id,
  //           authority.clone(),
  //           destination.clone(),
  //           source.clone());

  //   {
  //     let mut rng = thread_rng();

  //     rng.shuffle(&mut group_messages[..]);
  //     rng.shuffle(&mut group_keys_responses[..]);

  //     let mut resolved = None;
  //     let mut sentinel = Sentinel::new(&mut sentinel_messages);
  //     let mut rand: usize = rng.gen();
  //     let mut message_index = rand % group_messages.len();

  //     let msg = group_messages.remove(message_index);
  //     resolved =
  //         sentinel.add(
  //             msg.message_header,
  //             msg.message_type,
  //             msg.serialised_body,
  //             msg.signature);

  //     assert!(resolved.is_none());

  //     loop {
  //       if group_messages.is_empty() && group_keys_responses.is_empty() {
  //         break;
  //       }
  //       let messages_empty = group_messages.is_empty();
  //       let group_keys_responses_empty = group_keys_responses.is_empty();
  //       let mut group_keys_index;

  //       if !messages_empty {
  //         rand = rng.gen();
  //         message_index = rand % group_messages.len();
  //       } else {
  //         message_index = 1usize;
  //       }

  //       if !group_keys_responses_empty {
  //         rand = rng.gen();
  //         group_keys_index = rand % group_keys_responses.len();
  //       } else {
  //         group_keys_index = 0usize;
  //       }

  //       if (message_index % 2usize == 0) && !group_keys_responses_empty {
  //         let keys = group_keys_responses.remove(group_keys_index);
  //         resolved =
  //             sentinel.add(
  //                 keys.message_header,
  //                 keys.message_type,
  //                 keys.serialised_body,
  //                 keys.signature);

  //         if resolved.is_some() {
  //           break;
  //         }
  //       } else {
  //         if group_keys_responses_empty {
  //           rand = rng.gen();
  //           message_index = rand % group_messages.len();
  //         }
  //         let msg = group_messages.remove(message_index);
  //         resolved =
  //             sentinel.add(
  //                 msg.message_header,
  //                 msg.message_type,
  //                 msg.serialised_body,
  //                 msg.signature);

  //         if resolved.is_some() {
  //           break;
  //         }
  //       }
  //     }

  //     assert!(resolved.is_some());
  //   }
  // }

  // #[test]
  // fn fake_messages() {
  //   // network_size is the number of Pmid's created for test...
  //   let network_size = 1000usize;
  //   let mut sentinel_messages = SentinelMessages::new(network_size);
  //   let data = generate_data(64usize);
  //   let name = NameType::new(vector_as_u8_64_array(hash(&data[..]).0.to_vec()));
  //   let message_id = rand::random::<u32>() as types::MessageId;
  //   let destination = name.clone();
  //   let source = NameType::generate_random();
  //   let authority = Authority::ClientManager;
  //   let request = PutData{ name: name.clone(), data: data.clone() };
  //   let tag = MessageTypeTag::PutData;

  //   let mut fake_messages =
  //       sentinel_messages.fake_messages(
  //           request,
  //           tag,
  //           message_id,
  //           authority.clone(),
  //           destination.clone(),
  //           source.clone());

  //   let mut fake_group_keys_responses =
  //       sentinel_messages.fake_group_keys_responses(
  //           message_id,
  //           authority.clone(),
  //           destination.clone(),
  //           source.clone());

  //   {
  //     let mut rng = thread_rng();

  //     rng.shuffle(&mut fake_messages[..]);
  //     rng.shuffle(&mut fake_group_keys_responses[..]);

  //     let mut resolved = None;
  //     let mut sentinel = Sentinel::new(&mut sentinel_messages);
  //     let mut rand: usize = rng.gen();
  //     let mut message_index = rand % fake_messages.len();

  //     let msg = fake_messages.remove(message_index);
  //     resolved =
  //         sentinel.add(
  //             msg.message_header,
  //             msg.message_type,
  //             msg.serialised_body,
  //             msg.signature);

  //     assert!(resolved.is_none());

  //     loop {
  //       if fake_messages.is_empty() && fake_group_keys_responses.is_empty() {
  //         break;
  //       }
  //       let fake_messages_empty = fake_messages.is_empty();
  //       let fake_group_keys_responses_empty = fake_group_keys_responses.is_empty();
  //       let mut group_keys_index;

  //       if !fake_messages_empty {
  //         rand = rng.gen();
  //         message_index = rand % fake_messages.len();
  //       } else {
  //         message_index = 1usize;
  //       }

  //       if !fake_group_keys_responses_empty {
  //         rand = rng.gen();
  //         group_keys_index = rand % fake_group_keys_responses.len();
  //       } else {
  //         group_keys_index = 0usize;
  //       }

  //       if (message_index % 2usize == 0) && !fake_group_keys_responses_empty {
  //         let keys = fake_group_keys_responses.remove(group_keys_index);
  //         resolved =
  //             sentinel.add(
  //                 keys.message_header,
  //                 keys.message_type,
  //                 keys.serialised_body,
  //                 keys.signature);

  //         if resolved.is_some() {
  //           break;
  //         }
  //       } else {
  //         if fake_group_keys_responses_empty {
  //           rand = rng.gen();
  //           message_index = rand % fake_messages.len();
  //         }
  //         let msg = fake_messages.remove(message_index);
  //         resolved =
  //             sentinel.add(
  //                 msg.message_header,
  //                 msg.message_type,
  //                 msg.serialised_body,
  //                 msg.signature);

  //         if resolved.is_some() {
  //           break;
  //         }
  //       }
  //     }

  //     assert!(resolved.is_none());
  //   }
  // }

}
