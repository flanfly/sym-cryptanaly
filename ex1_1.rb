# Cipher ONE:
#
# m -> + -> u -> SBox -> v -> + -> c
#      ^                      ^
#      |                      |
#      k0                     k1
#
# Block size: 4 bits
# Key size: 2 * 4 bits

SBox = {
	0x0 => 0x6,
	0x1 => 0x4,
	0x2 => 0xc,
	0x3 => 0x5,
	0x4 => 0x0,
	0x5 => 0x7,
	0x6 => 0x2,
	0x7 => 0xe,
	0x8 => 0x1,
	0x9 => 0xf,
	0xa => 0x3,
	0xb => 0xd,
	0xc => 0x8,
	0xd => 0xa,
	0xe => 0x9,
	0xf => 0xb
}

SBox_inv = Hash[SBox.keys.map {|x| [SBox[x],x]}]

def encrypt(k0,k1,m)
	return SBox[m ^ k0] ^ k1
end

# Ex1.1: Differential cryptanalysis on Cipher ONE with three message/ciphertext pairs:

m0,c0 = 0x6,0x8
m1,c1 = 0x0,0xc
m2,c2 = 0xd,0xb

# Guess k1, compute SBox_inv[cx ^ k1] = ux, check if (m0 ^ m1) == (u0 ^ u1)

(0x0..0xf).each do |maybe_k1|
 u0,u1 = [c0,c1].map {|cx| SBox_inv[cx ^ maybe_k1] }

 if u0 ^ u1 == m0 ^ m1 then
	 puts "k1 candidate: #{maybe_k1.to_s(16)}"
	 maybe_k0 = u0 ^ m0
	 puts "k0 candidate: #{maybe_k0.to_s(16)}"

	 if encrypt(maybe_k0,maybe_k1,m2) == c2 then
		 puts "guessed right"
		 exit
	 else
		 puts "seems to be wrong"
	 end
 end
end

puts "No k1 candidate found :-("
