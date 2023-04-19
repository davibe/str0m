use std::time::Instant;

use crate::util::Soonest;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timeout {
    pub t: Option<Instant>,
    pub src: &'static str,
}

impl Timeout {
    pub fn new(t: Option<Instant>, src: &'static str) -> Timeout {
        Timeout { t, src }
    }
}

impl Soonest for Timeout {
    fn soonest(self, other: Self) -> Self {
        match (self.t, other.t) {
            (Some(v1), Some(v2)) => {
                if v1 < v2 {
                    self
                } else {
                    other
                }
            }
            (None, None) => Timeout::new(None, "none"),
            (None, Some(_)) => other,
            (Some(_), None) => self,
        }
    }
}
