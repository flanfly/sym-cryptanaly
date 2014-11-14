# Cipher TWO:
#
# m -> + -> u -> SBox -> v -> + -> w -> SBox -> x -> + -> c
#      ^                      ^                      ^
#      |                      |                      |
#      k0                     k1                     k2
#
# Block size: 4 bits
# Key size: 3 * 4 bits

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

def encrypt(k0,k1,k2,m)
	return SBox[SBox[m ^ k0] ^ k1] ^ k2
end

# Ex1.2: Differential cryptanalysis on Cipher TWO with four message/ciphertext pairs. Uses the characterisic 0xf -> 0xd:
#
# If u0 ^ u1 is 0xf, SBox[u0] ^ SBox[u1] is 0xd in 10 out of 16 times.

m0,c0 = 0x1,0xe
m1,c1 = 0xe,0x1
m2,c2 = 0x4,0x0
m3,c3 = 0xb,0x7

pairs = [
	[[m0,c0],[m1,c1]],
	[[m2,c2],[m3,c3]]
]
counter = Hash[]

# For all pairs mi,mj with mi ^ mj == 0xd: guess k2, compute SBox_inv[cx ^ k2] = ux, check if 0xd == (u0 ^ u1)
# Maintain a counter foreach guess and increment it if the above holds for a pair. The k2 candidate with the
# highest counter is likely the right key.

(0x0..0xf).each do |maybe_k2|
	counter[maybe_k2] = 0

	pairs.each do |p|
		mx,cx = p[0]
		my,cy = p[1]

		raise "Wrong differential" unless mx ^ my == 0xf

 		wx,wy = [cx,cy].map {|c| SBox_inv[c ^ maybe_k2] }
		counter[maybe_k2] += 1 if wx ^ wy == 0xd
	end
end

# For each k2 candidate repeat the one-round differential cryptanalysis of Ex1.1.
counter.to_a.sort {|a,b| a[1] <=> b[1]}.map {|a| a[0] }.reverse.each do |k2|
	(0x0..0xf).each do |maybe_k1|
		sane = pairs.reject do |p|
			mx,cx = p[0]
			my,cy = p[1]

			wx,wy = [cx,cy].map {|c| SBox_inv[c ^ k2] }
			ux,uy = [wx,wy].map {|w| SBox_inv[w ^ maybe_k1] }

			(ux ^ uy) != (mx ^ my)
		end

		if sane == pairs
			k1 = sane[0][0][0] ^ sane[0][0][1]

			puts "Key: #{k1.to_s(16)}, #{maybe_k1.to_s(16)}, #{k2.to_s(16)}"
			exit
		end
	end
end

puts "No key found :-("
