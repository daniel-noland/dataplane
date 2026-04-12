// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IPv4 options type.

/// IPv4 header options.
///
/// Wraps the raw options byte buffer from the IPv4 header. Options must be
/// a multiple of 4 bytes in length and at most 40 bytes (constrained by
/// the 4-bit IHL field).
///
// TODO: implement Parse/DeParse for standalone options parsing/serialization
// TODO: add typed Ipv4Option enum and iterator (etherparse has no element types)
// TODO: add mutation API (add/remove/modify individual options)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4Options(pub(in crate::ipv4) etherparse::Ipv4Options);

impl Ipv4Options {
    /// Maximum number of bytes that can be stored in IPv4 options.
    pub const MAX_LEN: usize = 40;

    /// Returns the options as a byte slice, or `None` if empty.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        if self.0.is_empty() {
            return None;
        }
        Some(self.0.as_slice())
    }

    /// Returns true if there are no options.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of bytes in the options.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::Ipv4Options;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for Ipv4Options {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            // IPv4 options must be a multiple of 4 bytes, max 40 bytes.
            // Generate a length: 0, 4, 8, ..., 40 (11 possible values).
            let len = u.produce::<u8>()? % 11 * 4;
            if len == 0 {
                return Some(Ipv4Options(etherparse::Ipv4Options::new()));
            }
            let mut buf = [0u8; 40];
            for byte in buf.iter_mut().take(len as usize) {
                *byte = u.produce()?;
            }
            // etherparse::Ipv4Options requires length to be a multiple of 4.
            // try_from validates this and returns BadOptionsLen on failure.
            let inner = etherparse::Ipv4Options::try_from(&buf[..len as usize])
                .unwrap_or_else(|_| unreachable!());
            Some(Ipv4Options(inner))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_options() {
        let opts = Ipv4Options(etherparse::Ipv4Options::new());
        assert!(opts.is_empty());
        assert_eq!(opts.len(), 0);
        assert_eq!(opts.as_bytes(), None);
    }

    #[test]
    fn options_len_consistency() {
        bolero::check!().with_type().for_each(|opts: &Ipv4Options| {
            if opts.is_empty() {
                assert_eq!(opts.len(), 0);
                assert_eq!(opts.as_bytes(), None);
            } else {
                assert!(!opts.is_empty());
                assert!(opts.len() <= Ipv4Options::MAX_LEN);
                assert_eq!(opts.len() % 4, 0);
                let bytes = opts.as_bytes().unwrap_or_else(|| unreachable!());
                assert_eq!(bytes.len(), opts.len());
            }
        });
    }
}
