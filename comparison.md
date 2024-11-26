# Comparing OpenSSL and p256 operations

Comparison of the verification routines as well as field/group element
definitions between the `p256` crate and the `prime256v1` OpenSSL implementation.

## Signature

Parsing the signature from the 32 byte `r` and `s` values.

### P256

```rust
let signature =
        Signature::try_from(signature).map_err(|_| PrecompileError::InvalidSignature)?;
```

### OpenSSL

```rust
let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_private_components(r_bignum, s_bignum)?;
```

---------->

```rust
/// Returns a new `EcdsaSig` by setting the `r` and `s` values associated with an ECDSA signature.
#[corresponds(ECDSA_SIG_set0)]
pub fn from_private_components(r: BigNum, s: BigNum) -> Result<EcdsaSig, ErrorStack> {
    unsafe {
        let sig = cvt_p(ffi::ECDSA_SIG_new())?;
        ECDSA_SIG_set0(sig, r.as_ptr(), s.as_ptr());
        mem::forget((r, s));
        Ok(EcdsaSig::from_ptr(sig))
    }
}
```

---------->

```C
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
        return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}
```
