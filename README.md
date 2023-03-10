# bagel [DRAFT]

(Binary [age](https://age-encryption.org/) aLternative)

I like `age`, but it has a text-based header format. I don't like text-based formats, so I'm specifying a binary alternative, because I think it's easier and less error-prone to parse. The threat model, semantics, and cryptographic properties of the format should be unchanged, it's just a different way of serialising the same information.

Actually, that's not quite true. I'm making two changes to the core cryptography:

- The nonce is now part of the header, and is included in the header's MAC calculation. This addresses a minor hypothetical weakness presented [here.](https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/appliedcrypto/education/theses/project_MircoStauble.pdf)

- The header is hashed before it is HMAC'd. ([rationale](https://github.com/C2SP/C2SP/issues/28))

**Currently, I'm not proposing this as a serious alternative to `age`. It's just a toy/prototype, and has not been extensively tested, audited, peer-reviewed, or even implemented yet. Significant changes may be made to this spec before it is considered "final" (if that ever happens at all!)**

If you know (or can calculate) the `file key` for an age file or a bagel file, you can convert one format into the other "losslessly", provided that the recipient types used are specified in both age and bagel formats (currently, that's X25519 and scrypt).

## Header

### Version Magic

The header begins with a 4 byte value, expressed in hexadecimal as `ba6e1500`.

This value was chosen for two reasons. The initial byte `0xba` is an invalid UTF8 starting byte, which makes it harder for someone to accidentally parse it as a string. It also has the most significant bit set, which means that if the file has been mangled through transmission over a 7-bit-only medium, then the corruption will be detected early.

Secondly, it kinda spells out "bagels".

The last byte acts as a version number ("0.0") and may be incremented in future revisions. Implementations should not attempt to parse versions that they do not recognise. Note that there is no need to parse out the version number specifically, the magic bytes should be treated as an opaque blob.

### Recipients

The version magic is followed by 1 or more Recipient structures. Every recipient entry shares the following top-level structure:

```
Type Length - a 1-byte unsigned integer
Type        - the recipient type string
Body Length - a 2-byte big-endian unsigned integer
Body        - an arbitrary number of bytes as specified by the Body Length field.
```

To maintain some level of interoperability with the `age` specification, the Type field is an ASCII string and must not include whitespace (i.e. each byte must be in the range 0x21-0x7e inclusive). Note that the string is *not* null-terminated.

The meaning of the Body bytes is specified on a per-recipient-type basis.

Note that the type length and body length values are inherently limited to 255 and 65535 respectively. This ought to be enough for anything (let me know if you disagree?)

A recipient of type length 0 acts as a sentinel value, and indicates the end of the recipients list. Note that this sentinel recipient still has a Body Length, which must also be zero.

### Nonce

The recipients are immediately followed by the 16-byte nonce value.

### Header MAC

The HMAC key is computed as specified in the `age` spec.

The header MAC is computed using HMAC-SHA-256, over the SHA-256 hash of all previous header bytes (including the Version Magic, and the Nonce). i.e.:

```
HMAC key = HKDF-SHA-256(ikm = file key, salt = empty, info = "header")
header MAC = HMAC-SHA-256(HMAC key, SHA-256(header bytes))
```

The MAC value is 32 bytes long and follows immediately after the Nonce.

## Payload

The payload is encoded exactly as in the `age` spec, except for the fact that the Nonce is not present (since it's already specified in the Header).

## Native recipient types

### The X25519 recipient type

This is semantically identical to as in the `age` spec. The type string used in the serialised Recipient structure is "X25519".

The serialised Recipient body always has length 64, and is comprised of the following fields:

```
ephemeral share    - 32 bytes
encrypted file key - 32 bytes (16 bytes of ciphertext and 16 bytes of auth tag)
```

These are the same values that would ordinarily be in the `age` text-based header, but as raw bytes instead of base64.

### The scrypt recipient type

This is semantically identical to as in the `age` spec. The type string used in the serialised Recipient structure is "scrypt".

The serialised Recipient body always has length 49 and is comprised of the following fields:

```
salt value         - 16 bytes
log2 work factor   - 1 byte unsigned integer
encrypted file key - 32 bytes (16 bytes of ciphertext and 16 bytes of auth tag)
```

Again, these are the same values that would ordinarily be in the `age` text-based header, but as raw bytes instead of base64.
