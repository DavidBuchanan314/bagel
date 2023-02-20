# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""
Reference implementation for Bech32 and segwit addresses.

Based on https://github.com/sipa/bech32/blob/15380f4d6c438a75e478ef73eca13f06fdaf1c02/ref/python/segwit_addr.py

Modified by David Buchanan for use in bagel, including adding exception handling.
"""


CHARSET = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
	"""Internal function that computes the Bech32 checksum."""
	generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
	chk = 1
	for value in values:
		top = chk >> 25
		chk = (chk & 0x1ffffff) << 5 ^ value
		for i in range(5):
			chk ^= generator[i] if ((top >> i) & 1) else 0
	return chk


def _bech32_hrp_expand(hrp):
	"""Expand the HRP into values for checksum computation."""
	return [x >> 5 for x in hrp] + [0] + [x & 0x1f for x in hrp]


def _bech32_verify_checksum(hrp, data):
	"""Verify a checksum given HRP and converted data characters."""
	if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
		raise ValueError("Invalid bech32 checksum")


def _bech32_create_checksum(hrp, data):
	"""Compute the checksum values given HRP and data."""
	values = _bech32_hrp_expand(hrp) + data
	polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
	return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_encode(hrp, data):
	"""Compute a Bech32 string given HRP and data values."""
	combined = data + _bech32_create_checksum(hrp, data)
	return hrp + b"1" + bytes(CHARSET[d] for d in combined)


def _bech32_decode(bech):
	"""Validate a Bech32 string, and determine HRP and data."""
	if ((any(x < 33 or x > 126 for x in bech)) or
			(bech.lower() != bech and bech.upper() != bech)):
		raise ValueError("Invalid bech32 string")
	bech = bech.lower()
	if b"1" not in bech:
		raise ValueError("Invalid bech32 string")
	pos = bech.rfind(b"1")
	if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
		raise ValueError("Invalid bech32 string")
	if not all(x in CHARSET for x in bech[pos+1:]):
		raise ValueError("Invalid bech32 string")
	hrp = bech[:pos]
	data = [CHARSET.find(x) for x in bech[pos+1:]]
	_bech32_verify_checksum(hrp, data)
	return (hrp, data[:-6])


def _convertbits(data, frombits, tobits, pad=True):
	"""General power-of-2 base conversion."""
	acc = 0
	bits = 0
	ret = []
	maxv = (1 << tobits) - 1
	max_acc = (1 << (frombits + tobits - 1)) - 1
	for value in data:
		if value < 0 or (value >> frombits):
			raise ValueError("Data value out of range")
		acc = ((acc << frombits) | value) & max_acc
		bits += frombits
		while bits >= tobits:
			bits -= tobits
			ret.append((acc >> bits) & maxv)
	if pad:
		if bits:
			ret.append((acc << (tobits - bits)) & maxv)
	elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
		raise ValueError("Trailing bits")
	return ret


def encode(hrp: bytes, data: bytes) -> bytes:
	return _bech32_encode(hrp, _convertbits(data, 8, 5))


def decode(expected_hrp: bytes, encoded: bytes) -> bytes:
	hrp, data = _bech32_decode(encoded)

	if hrp != expected_hrp:
		raise ValueError("Incorrect bech32 HRP value")

	return bytes(_convertbits(data, 5, 8, False))


if __name__ == "__main__":
	foo = encode(b"age", b"deadbeefcafebabedeadbeefcafebabe")
	print(foo)

	bar = decode(b"age", foo)
	print(bar)
