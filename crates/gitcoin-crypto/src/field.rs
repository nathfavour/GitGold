use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::ops::{Add, Div, Mul, Sub};

/// The prime modulus for GF(p): p = 2^256 - 189
fn prime() -> BigUint {
    let two = BigUint::from(2u32);
    two.pow(256) - BigUint::from(189u32)
}

/// An element in the finite field GF(p) where p = 2^256 - 189.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldElement {
    value: BigUint,
    modulus: BigUint,
}

impl FieldElement {
    /// Create a new field element, reducing value mod p.
    pub fn new(value: BigUint) -> Self {
        let modulus = prime();
        let value = value % &modulus;
        Self { value, modulus }
    }

    /// Create a field element from a u64.
    pub fn from_u64(v: u64) -> Self {
        Self::new(BigUint::from(v))
    }

    /// Create the zero element.
    pub fn zero() -> Self {
        Self::new(BigUint::zero())
    }

    /// Create the one element.
    pub fn one() -> Self {
        Self::new(BigUint::one())
    }

    /// Create a field element from big-endian bytes.
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        Self::new(BigUint::from_bytes_be(bytes))
    }

    /// Export to big-endian bytes, zero-padded to 32 bytes.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        let bytes = self.value.to_bytes_be();
        if bytes.len() >= 32 {
            bytes[bytes.len() - 32..].to_vec()
        } else {
            let mut padded = vec![0u8; 32 - bytes.len()];
            padded.extend_from_slice(&bytes);
            padded
        }
    }

    /// Returns the underlying BigUint value.
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Modular multiplicative inverse via Fermat's little theorem: a^(p-2) mod p.
    pub fn inv(&self) -> Self {
        assert!(!self.value.is_zero(), "cannot invert zero");
        let exp = &self.modulus - BigUint::from(2u32);
        let result = self.value.modpow(&exp, &self.modulus);
        Self {
            value: result,
            modulus: self.modulus.clone(),
        }
    }
}

impl Add for FieldElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let value = (&self.value + &rhs.value) % &self.modulus;
        Self {
            value,
            modulus: self.modulus,
        }
    }
}

impl Add for &FieldElement {
    type Output = FieldElement;
    fn add(self, rhs: Self) -> FieldElement {
        let value = (&self.value + &rhs.value) % &self.modulus;
        FieldElement {
            value,
            modulus: self.modulus.clone(),
        }
    }
}

impl Sub for FieldElement {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        // Add modulus to avoid underflow: (a - b + p) mod p
        let value = (&self.value + &self.modulus - &rhs.value) % &self.modulus;
        Self {
            value,
            modulus: self.modulus,
        }
    }
}

impl Sub for &FieldElement {
    type Output = FieldElement;
    fn sub(self, rhs: Self) -> FieldElement {
        let value = (&self.value + &self.modulus - &rhs.value) % &self.modulus;
        FieldElement {
            value,
            modulus: self.modulus.clone(),
        }
    }
}

impl Mul for FieldElement {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let value = (&self.value * &rhs.value) % &self.modulus;
        Self {
            value,
            modulus: self.modulus,
        }
    }
}

impl Mul for &FieldElement {
    type Output = FieldElement;
    fn mul(self, rhs: Self) -> FieldElement {
        let value = (&self.value * &rhs.value) % &self.modulus;
        FieldElement {
            value,
            modulus: self.modulus.clone(),
        }
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for FieldElement {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        self * rhs.inv()
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for &FieldElement {
    type Output = FieldElement;
    fn div(self, rhs: Self) -> FieldElement {
        self * &rhs.inv()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let a = FieldElement::from_u64(10);
        let b = FieldElement::from_u64(20);
        let c = a + b;
        assert_eq!(*c.value(), BigUint::from(30u32));
    }

    #[test]
    fn test_sub() {
        let a = FieldElement::from_u64(30);
        let b = FieldElement::from_u64(10);
        let c = a - b;
        assert_eq!(*c.value(), BigUint::from(20u32));
    }

    #[test]
    fn test_sub_underflow() {
        let a = FieldElement::from_u64(5);
        let b = FieldElement::from_u64(10);
        let c = a - b;
        // Should wrap: (5 - 10 + p) mod p = p - 5
        let expected = prime() - BigUint::from(5u32);
        assert_eq!(*c.value(), expected);
    }

    #[test]
    fn test_mul() {
        let a = FieldElement::from_u64(7);
        let b = FieldElement::from_u64(6);
        let c = a * b;
        assert_eq!(*c.value(), BigUint::from(42u32));
    }

    #[test]
    fn test_inv() {
        let a = FieldElement::from_u64(7);
        let a_inv = a.clone().inv();
        let product = a * a_inv;
        assert_eq!(*product.value(), BigUint::one());
    }

    #[test]
    fn test_div() {
        let a = FieldElement::from_u64(42);
        let b = FieldElement::from_u64(7);
        let c = a / b;
        assert_eq!(*c.value(), BigUint::from(6u32));
    }

    #[test]
    fn test_bytes_roundtrip() {
        let original = FieldElement::from_u64(123456789);
        let bytes = original.to_bytes_be();
        assert_eq!(bytes.len(), 32);
        let recovered = FieldElement::from_bytes_be(&bytes);
        assert_eq!(original, recovered);
    }

    #[test]
    #[should_panic(expected = "cannot invert zero")]
    fn test_inv_zero_panics() {
        let z = FieldElement::zero();
        z.inv();
    }

    #[test]
    fn test_one_times_x_is_x() {
        let x = FieldElement::from_u64(999);
        let one = FieldElement::one();
        let result = x.clone() * one;
        assert_eq!(result, x);
    }

    #[test]
    fn test_large_value_reduction() {
        // Value larger than p should be reduced
        let p = prime();
        let val = &p + BigUint::from(5u32);
        let elem = FieldElement::new(val);
        assert_eq!(*elem.value(), BigUint::from(5u32));
    }
}
