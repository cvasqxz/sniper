from binascii import b2a_hex, a2b_hex
from hashlib import sha256
import json, argparse

def calculate_txid(s):
    out = sha256(sha256(s).digest()).digest()
    return b2a_hex(out[::-1]).decode()


def b2a(s, pos, L):
	hex_stream = b2a_hex(s[pos:pos+L])
	return hex_stream.decode(), pos+L


def b2i(s, pos, L, endianess):
	byte = s[pos:pos+L]
	return int.from_bytes(byte, endianess), pos+L


def varint(s, pos):
	if s[pos] < 0xFD:
		return s[pos], pos+1
	
	off = 2**(s[pos] - 0xFC)

	output, c = b2i(s, pos+1, off, "little")
	return output, c-1


def decode(ascii_tx):
	c = 0
	tx = a2b_hex(ascii_tx)
	txid = calculate_txid(tx)

	nversion, c = b2i(tx, c, 4, "little")
	flag, c = b2i(tx, c, 2, "big")

	segwit_tx = (flag == 0x0001)

	if not segwit_tx:
		c -= 2

	len_inputs, c = varint(tx, c)

	inputs = []
	for vin in range(len_inputs):
		prevhash, c = b2a(tx, c, 32)
		vout, c = b2i(tx, c, 4, "little")
		lensigscript, c = varint(tx, c)
		sigscript, c = b2a(tx, c, lensigscript)
		sequence, c = b2i(tx, c, 4, "big")
		inputs.append({
				"prevhash": prevhash,
				"vout": vout,
				"sigscript": sigscript,
				"sequence": sequence
			})

	len_outputs, c = varint(tx, c)

	outputs = []
	for vout in range(len_outputs):
		satoshis, c = b2i(tx, c, 8, "little")
		lenredeemscript, c = varint(tx, c)
		redeemscript, c = b2a(tx, c, lenredeemscript)
		outputs.append({
			"sats": satoshis,
			"redeemscript": redeemscript
			})

	if flag:
		len_witnesses, c = varint(tx, c)

		witness_array = []
		for witness in range(len_witnesses):
			lenprogram, c = varint(tx, c)
			witnessprogram, c = b2a(tx, c, lenprogram)
			witness_array.append(witnessprogram)

	locktime, c = b2i(tx, c, 4, "little")

	decoded_tx = {
		"txid": txid,
		"size": len(tx),
		"nversion": nversion,
		"inputs": inputs,
		"outputs": outputs,
		"locktime": locktime
	}

	if flag:
		decoded_tx["witnesses"] = witness_array

	print(json.dumps(decoded_tx))


if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		prog='txsnipper.py',
		description='Proyecto Chaucha - 2022'
	)

	parser.add_argument("rawtx",
		help="Raw Bitcoin Transaction"
	)

	args = parser.parse_args()

	decode(args.rawtx)