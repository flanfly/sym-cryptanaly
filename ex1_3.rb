# Cipher THREE:
#
# m -> + -> SBox -> + -> SBox -> x -> + -> y -> SBox -> z -> + -> c
#      ^            ^                 ^                      ^
#      |            |                 |                      |
#      k0           k1                k2                     k3
#
# Block size: 4 bits
# Key size: 4 * 4 bits

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

# Ex1.3: Differential cryptanalysis on Cipher THREE with 16 message/ciphertext pairs. Uses the characterisic 0xf -> 0xd -> 0xc:
#
# If m0 ^ m1 is 0xf, SBox[x0] ^ SBox[x1] is 0xc in 1 out of 4 times.

# m -> c
known = {
	0x0 => 0x1,
	0x1 => 0xd,
	0x2 => 0x8,
	0x3 => 0xa,
	0x4 => 0x4,
	0x5 => 0x3,
	0x6 => 0x0,
	0x7 => 0x2,
	0x8 => 0xf,
	0x9 => 0x6,
	0xa => 0xe,
	0xb => 0xc,
	0xc => 0x5,
	0xd => 0xb,
	0xe => 0x7,
	0xf => 0x9
}
counter = Hash[]

# For all pairs mi,mj with mi ^ mj == 0xf: guess k3, compute SBox_inv[cx ^ k3] = yx, check if 0xc == (y0 ^ y1)
# Maintain a counter foreach guess and increment it if the above holds for a pair. The k3 candidate with the
# highest counter is likely the right key.
#
# We will only compute k3 this time.

(0x0..0xf).each do |maybe_k3|
	counter[maybe_k3] = 0

	known.each do |m0,c0|
		m1 = 0xf ^ m0
		c1 = known[m1]

		raise "Can't construct differential" unless c1 != nil

 		y0,y1 = [c0,c1].map {|c| SBox_inv[c ^ maybe_k3] }
		counter[maybe_k3] += 1 if y0 ^ y1 == 0xc
	end
end

counter.to_a.sort {|a,b| a[1] <=> b[1]}.map {|a| a[0] }.reverse[0..2].each do |k3|
	puts "Possible k3: #{k3.to_s(16)}"
end

# Now we could find k2, k1 and k0 as we did in Ex1.2 with differential f -> d
