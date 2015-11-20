
use sodiumoxide::crypto::sign;
use std::cmp::Ordering;

pub struct SignW(pub sign::Signature);

impl Clone for SignW {
    fn clone(&self) -> SignW {
        let mut bytes = [0u8; sign::SIGNATUREBYTES];
        for i in 0..sign::SIGNATUREBYTES {
            bytes[i] = (self.0).0[i]
        }
        SignW(sign::Signature(bytes))
    }
}

impl PartialOrd for SignW {
    fn partial_cmp(&self, other: &SignW) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for SignW {
    fn cmp(&self, other: &SignW) -> Ordering {
        for i in 0..sign::SIGNATUREBYTES {
            let ord = (self.0).0[i].cmp(&(other.0).0[i]);
            if ord != Ordering::Equal {
                return ord;
            }
        }
        Ordering::Equal
    }
}

impl PartialEq for SignW {
    fn eq(&self, other: &SignW) -> bool {
        for i in 0..sign::SIGNATUREBYTES {
            if (self.0).0[i] != (other.0).0[i] {
                return false;
            }
        }
        true
    }
}

impl Eq for SignW { }
