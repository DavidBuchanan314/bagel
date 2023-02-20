"""
This file acts as a minimal reference implementation of the "bagel" file format.

It is deliberately inflexible, only implementing the required features
with no thoughts given to performance, UX, or future extensibility.

WARNING WARNING WARNING
This is prototype-quality code, it may be entirely cryptographically broken
It's also the first implementation of bagel so there's nothing to test it against
"""

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import secrets
from dataclasses import dataclass
from typing import List, Dict
from functools import partial
from abc import ABC, abstractmethod

import bech32


BAGEL_V00_MAGIC = b"\xba\x6e\x15\x00"


@dataclass
class RecipientStanza(ABC):
	TYPE_NAME = None
	SERIALISED_LENGTH = None
	# Note: in theory, a recipient type could have variable length. No such
	# recipient types exist in this implementation, so we can hardcode it

	@abstractmethod
	def serialise_body(self) -> bytes:
		pass

	@classmethod
	@abstractmethod
	def from_bytes(cls, data: bytes) -> "RecipientStanza":
		"""
		Note: implementations may assume that the length of data passed in
		has already been verified
		"""
		pass


@dataclass
class SentinelRecipientStanza(RecipientStanza):
	TYPE_NAME = b""
	SERIALISED_LENGTH = 0

	def serialise_body(self) -> bytes:
		return b""

	@classmethod
	def from_bytes(self, data: bytes) -> "SentinelRecipientStanza":
		return SentinelRecipientStanza()


@dataclass
class X25519RecipientStanza(RecipientStanza):
	TYPE_NAME = b"X25519"
	SERIALISED_LENGTH = 32 + 32

	ephemeral_share:    bytes # 32
	encrypted_file_key: bytes # 32

	def serialise_body(self) -> bytes:
		return self.ephemeral_share + self.encrypted_file_key
	
	@classmethod
	def from_bytes(self, data: bytes) -> "X25519RecipientStanza":
		return X25519RecipientStanza(
			ephemeral_share=data[:32],
			encrypted_file_key=data[32:]
		)


@dataclass
class ScryptRecipientStanza(RecipientStanza):
	TYPE_NAME = b"scrypt"
	SERIALISED_LENGTH = 16 + 1 + 32

	salt:               bytes # 16
	log2_work_factor:   int
	encrypted_file_key: bytes # 32

	def serialise_body(self) -> bytes:
		return self.salt + bytes([self.log2_work_factor]) + self.encrypted_file_key
	
	@classmethod
	def from_bytes(self, data: bytes) -> "ScryptRecipientStanza":
		return ScryptRecipientStanza(
			salt=data[:16],
			log2_work_factor=data[16],
			encrypted_file_key=data[16+1:]
		)


RECIPIENT_TYPE_MAP: Dict[bytes, RecipientStanza] = {
	SentinelRecipientStanza.TYPE_NAME: SentinelRecipientStanza,
	X25519RecipientStanza.TYPE_NAME:   X25519RecipientStanza,
	ScryptRecipientStanza.TYPE_NAME:   ScryptRecipientStanza,
}


def HKDF_SHA256_32(ikm: bytes, salt: bytes, info: bytes):
	hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
	return hkdf.derive(ikm)


def write_and_hash(stream, hash, data):
	stream.write(data)
	hash.update(data)


def read_exact(stream, n, hash=None):
	data = stream.read(n)

	if len(data) != n:
		raise EOFError("Unexpected end of stream")

	if hash is not None:
		hash.update(data)
	
	return data


class BagelWriter:
	def __init__(self,
		x25519_recipients: List[bytes]=[],
		scrypt_passphrase: bytes=None
	):
		if scrypt_passphrase is not None and x25519_recipients:
			raise Exception("scrypt cannot be used in combination with x25519 recipients")

		self._x25519_recipients = [
			X25519PublicKey.from_public_bytes(
				bech32.decode(b"age", encoded_pubkey)
			)
			for encoded_pubkey in x25519_recipients
		]

		self._scrypt_passphrase = scrypt_passphrase
	
	def encrypt(self, dest, source):
		file_key = secrets.token_bytes(16)
		nonce = secrets.token_bytes(32)

		# RECIPIENT WRAPPING
		recipient_stanzas: List[RecipientStanza] = []
		recipient_stanzas += map(
			partial(self._wrap_x25519_recipient, file_key),
			self._x25519_recipients
		)
		if self._scrypt_passphrase is not None:
			recipient_stanzas.append(
				self._wrap_scrypt_recipient(file_key, self._scrypt_passphrase)
			)
		recipient_stanzas.append(SentinelRecipientStanza())

		# HEADER WRITING
		h = hashes.Hash(hashes.SHA256())
		write_and_hash(dest, h, BAGEL_V00_MAGIC)

		for stanza in recipient_stanzas:
			write_and_hash(dest, h,
				bytes([len(stanza.TYPE_NAME)])
				+ stanza.TYPE_NAME
			)
			body = stanza.serialise_body()
			write_and_hash(dest, h,
				len(body).to_bytes(2, "big")
				+ body
			)
		
		write_and_hash(dest, h, nonce)

		header_hash = h.finalize()
		hmac_key = HKDF_SHA256_32(ikm=file_key, salt=b"", info=b"header")
		hm = hmac.HMAC(hmac_key, hashes.SHA256())
		hm.update(header_hash)
		header_mac = hm.finalize()

		dest.write(header_mac)

		# PAYLOAD WRITING
		payload_key = HKDF_SHA256_32(ikm=file_key, salt=nonce, info=b"payload")
		cipher = ChaCha20Poly1305(key=payload_key)
		for chunk_index, is_last, chunk in self._enumerate_chunks(source):
			dest.write(cipher.encrypt(
				nonce=chunk_index.to_bytes(11, "big") + bytes([is_last]),
				data=chunk,
				associated_data=b""
			))

	def _enumerate_chunks(self, stream):
		chunk = stream.read(0x10000)
		chunk_index = 0
		while True:
			# clever trick: if the next chunk would be empty, the "current"
			# chunk must be the last
			next_chunk = stream.read(0x10000)
			is_last = not next_chunk
			yield chunk_index, is_last, chunk
			if is_last:
				break
			chunk = next_chunk
			chunk_index += 1
			

	def _wrap_x25519_recipient(self,
		file_key: bytes,
		recipient_pubkey: X25519PublicKey
	) -> X25519RecipientStanza:

		ephemeral_secret = X25519PrivateKey.generate()
		ephemeral_share = ephemeral_secret.public_key()

		salt = ephemeral_share.public_bytes_raw() + recipient_pubkey.public_bytes_raw()
		info = b"age-encryption.org/v1/X25519"
		shared_secret = ephemeral_secret.exchange(recipient_pubkey)

		wrap_key = HKDF_SHA256_32(
			ikm=shared_secret,
			salt=salt,
			info=info
		)

		encrypted_file_key = ChaCha20Poly1305(key=wrap_key).encrypt(
			nonce=bytes(12),
			data=file_key,
			associated_data=b""
		)

		return X25519RecipientStanza(
			ephemeral_share=ephemeral_share.public_bytes_raw(),
			encrypted_file_key=encrypted_file_key
		)


	def _wrap_scrypt_recipient(self,
		file_key: bytes,
		passphrase: bytes,
		log2_work_factor: int=14
	) -> ScryptRecipientStanza:

		salt = secrets.token_bytes(16)
		wrap_key= Scrypt(
			salt=b"age-encryption.org/v1/scrypt" + salt,
			length=32,
			n=2**log2_work_factor,
			r=8,
			p=1,
		).derive(passphrase)

		encrypted_file_key = ChaCha20Poly1305(key=wrap_key).encrypt(
			nonce=bytes(12),
			data=file_key,
			associated_data=b""
		)

		return ScryptRecipientStanza(
			salt=salt,
			log2_work_factor=log2_work_factor,
			encrypted_file_key=encrypted_file_key
		)


class BagelReader:
	def __init__(self,
		x25519_identities: List[bytes]=[],
		scrypt_passphrase_callback=None
	):
		self._x25519_identities = [
			X25519PrivateKey.from_private_bytes(
				bech32.decode(b"age-secret-key-", encoded_privkey)
			)
			for encoded_privkey in x25519_identities
		]

		self._scrypt_passphrase_callback = scrypt_passphrase_callback
	
	def decrypt(self, dest, source):
		h = hashes.Hash(hashes.SHA256())

		magic = read_exact(source, len(BAGEL_V00_MAGIC), h)
		if magic != BAGEL_V00_MAGIC:
			raise ValueError(f"bagel: Bad magic bytes! Read {magic}, expected {BAGEL_V00_MAGIC}")
		
		# XXX: if the input file were particularly evil, it could contain an
		# unbounded number of recipients until we run out of memory trying
		# to parse it. This could be worked around by using a state machine to
		# process the recipients mid-parse, 
		recipient_stanzas = []
		while True:
			recipient_type_length = read_exact(source, 1, h)[0]
			recipient_type = read_exact(source, recipient_type_length, h)

			if not all(0x21 <= x <= 0xfe for x in recipient_type):
				raise ValueError(f"Invalid recipient_type: {recipient_type} (contains values outside 0x21-0xfe)")
			
			recipient_body_length = int.from_bytes(read_exact(source, 2, h), "big")
			recipient_body = read_exact(source, recipient_body_length, h)

			# XXX: name this variable better
			recip = RECIPIENT_TYPE_MAP.get(recipient_type)

			if recip is None:
				print(f"INFO: unrecognised recipient type {recipient_type}, skipping.")
				continue

			if len(recipient_body) != recip.SERIALISED_LENGTH:
				raise Exception(
					f"Invalid body length ({len(recipient_body)}) "
					"for recipient type {recipient_type} "
					"(expected {recip.SERIALISED_LENGTH})"
				)
			
			parsed_recipient = recip.from_bytes(recipient_body)

			if type(parsed_recipient) is SentinelRecipientStanza:
				break

			recipient_stanzas.append(parsed_recipient)
		
		nonce = read_exact(source, 32, h)
		header_mac = read_exact(source, 32)

		# at this point, the recipient_stanzas list contains some combination
		# of X25519 or Scrypt stanzas.

		file_key = None
		if any(type(s) is ScryptRecipientStanza for s in recipient_stanzas):
			if len(recipient_stanzas) != 1:
				raise Exception("Scrypt recipient stanza found, but there were other stanzas")
			
			passphrase = self._scrypt_passphrase_callback()
			file_key = self._unwrap_scrypt_stanza(recipient_stanzas[0], passphrase)
		else:
			# at this point, recipient_stanzas is all X25519
			for stanza in recipient_stanzas:
				assert(type(stanza) is X25519RecipientStanza)
				for privkey in self._x25519_identities:
					try:
						file_key = self._unwrap_x25519_stanza(stanza, privkey)
						break
					except:
						pass

				if file_key is not None:
					break
		
		if file_key is None:
			raise Exception("Failed to derive file key :(")

		# before we go any further, we need to verify the header MAC

		header_hash = h.finalize()
		hmac_key = HKDF_SHA256_32(ikm=file_key, salt=b"", info=b"header")
		hm = hmac.HMAC(hmac_key, hashes.SHA256())
		hm.update(header_hash)
		hm.verify(header_mac)

		# now we can derive the payload key
		payload_key = HKDF_SHA256_32(ikm=file_key, salt=nonce, info=b"payload")
		cipher = ChaCha20Poly1305(key=payload_key)
		for chunk_index, is_last, chunk in self._enumerate_chunks(source):
			dest.write(cipher.decrypt(
				nonce=chunk_index.to_bytes(11, "big") + bytes([is_last]),
				data=chunk,
				associated_data=b""
			))
	
	def _unwrap_x25519_stanza(self, stanza: X25519RecipientStanza, privkey: X25519PrivateKey):
		salt = stanza.ephemeral_share + privkey.public_key().public_bytes_raw()
		info = b"age-encryption.org/v1/X25519"
		shared_secret = privkey.exchange(
			X25519PublicKey.from_public_bytes(stanza.ephemeral_share)
		)

		wrap_key = HKDF_SHA256_32(
			ikm=shared_secret,
			salt=salt,
			info=info
		)

		file_key = ChaCha20Poly1305(key=wrap_key).decrypt(
			nonce=bytes(12),
			data=stanza.encrypted_file_key,
			associated_data=b""
		)

		return file_key

	def _unwrap_scrypt_stanza(self, stanza: ScryptRecipientStanza, passphrase: bytes):
		wrap_key = Scrypt(
			salt=b"age-encryption.org/v1/scrypt" + stanza.salt,
			length=32,
			n=2**stanza.log2_work_factor,
			r=8,
			p=1,
		).derive(passphrase)

		file_key = ChaCha20Poly1305(key=wrap_key).decrypt(
			nonce=bytes(12),
			data=stanza.encrypted_file_key,
			associated_data=b""
		)

		return file_key

	def _enumerate_chunks(self, stream):
		"""
		Returns an iterator over the payload chunks, with each element in the
		format: (chunk_counter, is_last_chunk, chunk_data)
		"""
		# We maintain a small "read ahead" buffer which allows us to detect EOF
		# before it happens (important when the last block is a full one).
		# This buffer could be a single byte long, but the numbers are nice and
		# round with a buffer size of 0x10 (since that's also the auth tag size)
		read_ahead = stream.read(0x10)
		chunk_counter = 0
		while True:
			chunk = read_ahead + stream.read(0x10000)
			if len(chunk) < 0x10:
				raise ValueError("Unexpected EOF - truncated payload?")
			read_ahead = stream.read(0x10)
			is_last = not read_ahead
			yield chunk_counter, is_last, chunk
			if is_last:
				return
			chunk_counter += 1



if __name__ == "__main__":
	import io
	import os
	import sys

	# test scrypt roundtrip:
	payload = io.BytesIO(b"Hello, scrypt world!\n")
	passphrase = b"hello"
	bagel_writer = BagelWriter(scrypt_passphrase=passphrase)

	with open("test.bagel", "wb") as outfile:
		bagel_writer.encrypt(outfile, payload)


	bagel_reader = BagelReader(scrypt_passphrase_callback=lambda: b"hello")

	with open("test.bagel", "rb") as infile:
		bagel_reader.decrypt(sys.stderr.buffer, infile)
		sys.stderr.buffer.flush()
	

	# test x25519 roundtrip:
	payload = io.BytesIO(b"Hello, X25519 world!\n")
	bagel_writer = BagelWriter(x25519_recipients=[
		b"age1v9s76v6u5p8fhf2srzdfymwsque0vfrlkxfzua54uzwksfq3ssms5ea5p9",
		b"age1nuer22lcls0c5ywpqd9ze5a0qv9np4vhaxrwfwrstlf2funxtq8swl258l", # the one we have a privkey for
		b"age1z9p6j595uhchsxm96hrhqrmc5sp00q6q8kknap57h4ag44s3dvpqylck67"
	])

	with open("test2.bagel", "wb") as outfile:
		bagel_writer.encrypt(outfile, payload)


	bagel_reader = BagelReader(x25519_identities=[
		b"AGE-SECRET-KEY-14772K6UFPKHF6QCKCJEZYDJLRDMVHSMQSWK6J2000HYKKGXQ7CWS8GJHYE",
		b"AGE-SECRET-KEY-14DW8L2NDGDUWU4YMTQD2YSLKS8WFVWE0574LR7HMQJRMAR5PPXKSLV72A0", # the one that matches the above pubkey
		b"AGE-SECRET-KEY-1F05MLJQHP9VF9J8Z58JML59H26P3SNKSQVH9T0GCLJNFYU966SHQ0WSECE"
	])

	with open("test2.bagel", "rb") as infile:
		bagel_reader.decrypt(sys.stderr.buffer, infile)
		sys.stderr.buffer.flush()
	

	def test_roundtrip(data):
		payload = io.BytesIO(data)
		bagel_writer = BagelWriter(x25519_recipients=[
			b"age1nuer22lcls0c5ywpqd9ze5a0qv9np4vhaxrwfwrstlf2funxtq8swl258l", # the one we have a privkey for
		])

		with open("test3.bagel", "wb") as outfile:
			bagel_writer.encrypt(outfile, payload)


		bagel_reader = BagelReader(x25519_identities=[
			b"AGE-SECRET-KEY-14DW8L2NDGDUWU4YMTQD2YSLKS8WFVWE0574LR7HMQJRMAR5PPXKSLV72A0", # the one that matches the above pubkey
		])

		dest = io.BytesIO()
		with open("test3.bagel", "rb") as infile:
			bagel_reader.decrypt(dest, infile)
		
		assert(dest.getvalue() == data)
	
	test_roundtrip(b"")
	test_roundtrip(b"a")
	test_roundtrip(os.urandom(0x10000))
	test_roundtrip(os.urandom(0x10000 - 1))
	test_roundtrip(os.urandom(0x10000 + 1))
	test_roundtrip(os.urandom(0x100000 - 1234))

