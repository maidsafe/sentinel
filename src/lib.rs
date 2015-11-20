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

//! Sentinel cryptographically confirms the origin of a claim in a decentralised network.
//!
//! A claim has to implement Claimable in order to be verifiable and mergeable.
//! A request has to implement GetSigningKeys such that Sentinel can acquire
//! the necessary public signing keys.
//! The request is passed immutably through sentinel
//! and is used as a key to group claims and corresponding keys.
//! When sentinel resolves a threshold on verified and merged message,
//! it returns the requester key and the merged claim.
//! Claimant names and associated signatures are discarded after successful resolution,
//! as such abstracting the original request into a resolved claim.
//!
//! The keys_threshold specifies a minimal threshold on the number of independent mentions of
//! a single public signing key needed to consider it for verifying a claim.  This threshold
//! can be one or higher.
//! The claims_threshold specifies a minimal threshold on the number of verified claims before
//! sentinel will attempt to merge these verified claims.

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/sentinel")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]

extern crate rustc_serialize;
extern crate accumulator;
extern crate lru_time_cache;
extern crate sodiumoxide;
extern crate cbor;
extern crate rand;

use sodiumoxide::crypto;
use sodiumoxide::crypto::sign::verify_detached;
use sodiumoxide::crypto::sign::PublicKey;
use sodiumoxide::crypto::sign::Signature;

pub type SerialisedClaim = Vec<u8>;

/// Sentinel provides a consensus mechanism on all content messages.
/// The claims made must be identical and cryptographically signed.
pub mod pure_sentinel;
mod key_store;
pub mod key_sentinel;
mod wrappers;
mod refresh_sentinel;
mod statistics;

fn verify_signature(signature: &Signature,
                    public_key: &PublicKey,
                    claim: &SerialisedClaim)
                    -> Option<SerialisedClaim> {

    match crypto::sign::verify_detached(&signature, claim, public_key) {
        true => Some(claim.clone()),
        false => None,
    }
}
