//! Abstract Domains for Program Analysis
//!
//! Defines various abstract domains beyond intervals.

use serde::{Deserialize, Serialize};

/// Sign domain: Negative, Zero, Positive
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Sign {
    Negative,
    Zero,
    Positive,
    NonNegative, // >= 0
    NonPositive, // <= 0
    NonZero,
    Top,    // Any
    Bottom, // Empty
}

impl Sign {
    pub fn from_value(v: i128) -> Self {
        if v < 0 {
            Sign::Negative
        } else if v == 0 {
            Sign::Zero
        } else {
            Sign::Positive
        }
    }

    pub fn join(&self, other: &Sign) -> Sign {
        use Sign::*;
        match (self, other) {
            (Bottom, x) | (x, Bottom) => *x,
            (Top, _) | (_, Top) => Top,
            (x, y) if x == y => *x,
            (Zero, Positive) | (Positive, Zero) => NonNegative,
            (Zero, Negative) | (Negative, Zero) => NonPositive,
            (Positive, Negative) | (Negative, Positive) => NonZero,
            (NonNegative, Negative) | (Negative, NonNegative) => Top,
            (NonPositive, Positive) | (Positive, NonPositive) => Top,
            _ => Top,
        }
    }

    pub fn add(&self, other: &Sign) -> Sign {
        use Sign::*;
        match (self, other) {
            (Bottom, _) | (_, Bottom) => Bottom,
            (Zero, x) | (x, Zero) => *x,
            (Positive, Positive) => Positive,
            (Negative, Negative) => Negative,
            _ => Top,
        }
    }

    pub fn mul(&self, other: &Sign) -> Sign {
        use Sign::*;
        match (self, other) {
            (Bottom, _) | (_, Bottom) => Bottom,
            (Zero, _) | (_, Zero) => Zero,
            (Positive, Positive) | (Negative, Negative) => Positive,
            (Positive, Negative) | (Negative, Positive) => Negative,
            _ => Top,
        }
    }
}

/// Congruence domain: x ≡ r (mod m)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Congruence {
    pub modulus: u64,
    pub remainder: u64,
}

impl Congruence {
    pub fn new(modulus: u64, remainder: u64) -> Self {
        Self {
            modulus,
            remainder: remainder % modulus.max(1),
        }
    }

    pub fn singleton(value: u64) -> Self {
        Self {
            modulus: 0,
            remainder: value,
        }
    }

    pub fn top() -> Self {
        Self {
            modulus: 1,
            remainder: 0,
        }
    }

    pub fn contains(&self, value: u64) -> bool {
        if self.modulus == 0 {
            value == self.remainder
        } else {
            value % self.modulus == self.remainder
        }
    }

    pub fn join(&self, other: &Congruence) -> Congruence {
        if self.modulus == 0 && other.modulus == 0 {
            if self.remainder == other.remainder {
                *self
            } else {
                // GCD of difference is new modulus
                let diff = self.remainder.abs_diff(other.remainder);
                Congruence::new(diff, self.remainder % diff)
            }
        } else if self.modulus == 0 {
            Congruence::new(
                gcd(other.modulus, abs_diff(self.remainder, other.remainder)),
                self.remainder % other.modulus.max(1),
            )
        } else {
            Congruence::new(
                gcd(
                    gcd(self.modulus, other.modulus),
                    abs_diff(self.remainder, other.remainder),
                ),
                self.remainder % other.modulus.max(1),
            )
        }
    }
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

fn abs_diff(a: u64, b: u64) -> u64 {
    a.abs_diff(b)
}

/// Bitfield domain for tracking which bits might be set
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bitfield {
    /// Bits that are definitely 0
    pub zeros: u64,
    /// Bits that are definitely 1
    pub ones: u64,
}

impl Bitfield {
    pub fn new(zeros: u64, ones: u64) -> Self {
        Self { zeros, ones }
    }

    pub fn singleton(value: u64) -> Self {
        Self {
            zeros: !value,
            ones: value,
        }
    }

    pub fn top() -> Self {
        Self { zeros: 0, ones: 0 }
    }

    pub fn contains(&self, value: u64) -> bool {
        (value & self.zeros) == 0 && (!value & self.ones) == 0
    }

    pub fn join(&self, other: &Bitfield) -> Bitfield {
        Bitfield {
            zeros: self.zeros & other.zeros,
            ones: self.ones & other.ones,
        }
    }

    pub fn bitwise_and(&self, other: &Bitfield) -> Bitfield {
        Bitfield {
            zeros: self.zeros | other.zeros,
            ones: self.ones & other.ones,
        }
    }

    pub fn bitwise_or(&self, other: &Bitfield) -> Bitfield {
        Bitfield {
            zeros: self.zeros & other.zeros,
            ones: self.ones | other.ones,
        }
    }
}

/// Product domain combining multiple domains
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductDomain {
    pub sign: Sign,
    pub congruence: Congruence,
    pub bitfield: Bitfield,
}

impl ProductDomain {
    pub fn from_value(value: i128) -> Self {
        let u_value = value.unsigned_abs() as u64;
        Self {
            sign: Sign::from_value(value),
            congruence: Congruence::singleton(u_value),
            bitfield: Bitfield::singleton(u_value),
        }
    }

    pub fn top() -> Self {
        Self {
            sign: Sign::Top,
            congruence: Congruence::top(),
            bitfield: Bitfield::top(),
        }
    }

    pub fn join(&self, other: &ProductDomain) -> ProductDomain {
        ProductDomain {
            sign: self.sign.join(&other.sign),
            congruence: self.congruence.join(&other.congruence),
            bitfield: self.bitfield.join(&other.bitfield),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_domain() {
        assert_eq!(Sign::from_value(-5), Sign::Negative);
        assert_eq!(Sign::from_value(0), Sign::Zero);
        assert_eq!(Sign::from_value(10), Sign::Positive);
    }

    #[test]
    fn test_congruence_domain() {
        let even = Congruence::new(2, 0);
        assert!(even.contains(0));
        assert!(even.contains(2));
        assert!(even.contains(100));
        assert!(!even.contains(1));
        assert!(!even.contains(99));
    }

    #[test]
    fn test_bitfield_domain() {
        let bf = Bitfield::singleton(0b1010);
        assert!(bf.contains(0b1010));
        assert!(!bf.contains(0b1011));
    }
}
