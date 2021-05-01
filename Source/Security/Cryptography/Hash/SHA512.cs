using System;

using Litdex.Utilities;
using Litdex.Utilities.Extension;

namespace Litdex.Security.Cryptography.Hash
{
	/// <summary>
	///		Implementation of SHA-2 512 bit.
	/// </summary>
	public class SHA512 : BaseSHA
	{
		#region Member

		private ulong H1, H2, H3, H4, H5, H6, H7, H8;
		private readonly ulong[] W = new ulong[80];
		private int wOff;

		/// <summary>
		///		SHA-384 and SHA-512 Constants.
		///		represent the first 64 bits of the fractional parts of the
		///		cube roots of the first sixty-four prime numbers.
		/// </summary>
		private readonly ulong[] K =
		{
			0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
			0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
			0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
			0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
			0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
			0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
			0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
			0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
			0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
			0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
			0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
			0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
			0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
			0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
			0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
			0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
			0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
			0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
			0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
			0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
		};

		#endregion Member

		#region Constructor & Destructor

		/// <summary>
		///		Create an instance of <see cref="SHA512"/> object.
		/// </summary>
		public SHA512()
		{
			this.xBuf = new byte[8];
			this.DigestLength = 64;
			this.ByteLength = 128;
			this.byteCount = new long[2];
			this.Reset();
		}

		/// <summary>
		///		Destructor.
		/// </summary>
		~SHA512()
		{
			this.Reset();
			this.K.Clear();
		}

		#endregion Constructor & Destructor

		#region Private Method

		/// <summary>
		/// SHA-512 initial hash value.
		/// The first 64 bits of the fractional parts of
		/// the square roots of the first eight prime numbers.
		/// </summary>
		private void InitalizeHashValue()
		{
			this.H1 = 0x6a09e667f3bcc908;
			this.H2 = 0xbb67ae8584caa73b;
			this.H3 = 0x3c6ef372fe94f82b;
			this.H4 = 0xa54ff53a5f1d36f1;
			this.H5 = 0x510e527fade682d1;
			this.H6 = 0x9b05688c2b3e6c1f;
			this.H7 = 0x1f83d9abfb41bd6b;
			this.H8 = 0x5be0cd19137e2179;
		}

		internal override void Finish()
		{
			this.AdjustByteCounts();

			long lowBitLength = this.byteCount[0] << 3;
			long hiBitLength = this.byteCount[1];

			//
			// add the pad bytes.
			//
			this.Update(128);

			while (this.xBufOff != 0)
			{
				this.Update(0);
			}

			this.ProcessLength(lowBitLength, hiBitLength);

			this.ProcessBlock();
		}

		internal override void ProcessLength(long bitLength)
		{
			throw new NotImplementedException();
		}

		internal override void ProcessWord(byte[] input, int inOff)
		{
			this.W[this.wOff] = Pack.BE_To_UInt64(input, inOff);

			if (++this.wOff == 16)
			{
				this.ProcessBlock();
			}
		}

		/// <summary>
		///		Adjust the byte counts so that byteCount2 represents the
		///		upper long (less 3 bits) word of the byte count.
		/// </summary>
		private void AdjustByteCounts()
		{
			if (this.byteCount[0] > 0x1fffffffffffffffL)
			{
				this.byteCount[2] += (long)((ulong)this.byteCount[0] >> 61);
				this.byteCount[0] &= 0x1fffffffffffffffL;
			}
		}

		internal void ProcessLength(long lowW, long hiW)
		{
			if (this.wOff > 14)
			{
				this.ProcessBlock();
			}

			this.W[14] = (ulong)hiW;
			this.W[15] = (ulong)lowW;
		}

		internal override void ProcessBlock()
		{
			this.AdjustByteCounts();

			//
			// expand 16 word block into 80 word blocks.
			//
			for (int ti = 16; ti <= 79; ++ti)
			{
				this.W[ti] = this.Sigma1(this.W[ti - 2]) + this.W[ti - 7] + this.Sigma0(this.W[ti - 15]) + this.W[ti - 16];
			}

			//
			// set up working variables.
			//
			ulong a = this.H1;
			ulong b = this.H2;
			ulong c = this.H3;
			ulong d = this.H4;
			ulong e = this.H5;
			ulong f = this.H6;
			ulong g = this.H7;
			ulong h = this.H8;

			int t = 0;
			for (int i = 0; i < 10; i++)
			{
				// t = 8 * i
				h += this.Sum1(e) + this.Ch(e, f, g) + this.K[t] + this.W[t++];
				d += h;
				h += this.Sum0(a) + this.Maj(a, b, c);

				// t = 8 * i + 1
				g += this.Sum1(d) + this.Ch(d, e, f) + this.K[t] + this.W[t++];
				c += g;
				g += this.Sum0(h) + this.Maj(h, a, b);

				// t = 8 * i + 2
				f += this.Sum1(c) + this.Ch(c, d, e) + this.K[t] + this.W[t++];
				b += f;
				f += this.Sum0(g) + this.Maj(g, h, a);

				// t = 8 * i + 3
				e += this.Sum1(b) + this.Ch(b, c, d) + this.K[t] + this.W[t++];
				a += e;
				e += this.Sum0(f) + this.Maj(f, g, h);

				// t = 8 * i + 4
				d += this.Sum1(a) + this.Ch(a, b, c) + this.K[t] + this.W[t++];
				h += d;
				d += this.Sum0(e) + this.Maj(e, f, g);

				// t = 8 * i + 5
				c += this.Sum1(h) + this.Ch(h, a, b) + this.K[t] + this.W[t++];
				g += c;
				c += this.Sum0(d) + this.Maj(d, e, f);

				// t = 8 * i + 6
				b += this.Sum1(g) + this.Ch(g, h, a) + this.K[t] + this.W[t++];
				f += b;
				b += this.Sum0(c) + this.Maj(c, d, e);

				// t = 8 * i + 7
				a += this.Sum1(f) + this.Ch(f, g, h) + this.K[t] + this.W[t++];
				e += a;
				a += this.Sum0(b) + this.Maj(b, c, d);
			}

			this.H1 += a;
			this.H2 += b;
			this.H3 += c;
			this.H4 += d;
			this.H5 += e;
			this.H6 += f;
			this.H7 += g;
			this.H8 += h;

			//
			// reset the offset and clean out the word buffer.
			//
			this.wOff = 0;
			Array.Clear(this.W, 0, 16);
		}

		/// <summary>
		///		SHA-384 and SHA-512 functions (as for SHA-256 but for longs)
		/// </summary>
		/// <param name="x"></param>
		/// <param name="y"></param>
		/// <param name="z"></param>
		/// <returns></returns>
		private ulong Ch(ulong x, ulong y, ulong z)
		{
			return (x & y) ^ (~x & z);
		}

		private ulong Maj(ulong x, ulong y, ulong z)
		{
			return (x & y) ^ (x & z) ^ (y & z);
		}

		private ulong Sum0(ulong x)
		{
			return ((x << 36) | (x >> 28)) ^ ((x << 30) | (x >> 34)) ^ ((x << 25) | (x >> 39));
		}

		private ulong Sum1(ulong x)
		{
			return ((x << 50) | (x >> 14)) ^ ((x << 46) | (x >> 18)) ^ ((x << 23) | (x >> 41));
		}

		private ulong Sigma0(ulong x)
		{
			return ((x << 63) | (x >> 1)) ^ ((x << 56) | (x >> 8)) ^ (x >> 7);
		}

		private ulong Sigma1(ulong x)
		{
			return ((x << 45) | (x >> 19)) ^ ((x << 3) | (x >> 61)) ^ (x >> 6);
		}

		#endregion Private Method

		#region Public Method

		/// <inheritdoc/>
		public override string AlgorithmName()
		{
			return "SHA 2 - 512";
		}

		/// <inheritdoc/>
		public override void Reset()
		{
			this.byteCount[0] = 0;
			this.byteCount[1] = 0;

			this.xBufOff = 0;
			Array.Clear(this.xBuf, 0, this.xBuf.Length);

			this.wOff = 0;
			Array.Clear(this.W, 0, this.W.Length);

			this.InitalizeHashValue();
		}

		/// <inheritdoc/>
		public override int GetHashLength()
		{
			return this.DigestLength;
		}

		/// <inheritdoc/>
		public override int GetByteLength()
		{
			return this.ByteLength;
		}

		/// <inheritdoc/>
		public override void Update(byte input)
		{
			this.xBuf[this.xBufOff++] = input;

			if (this.xBufOff == this.xBuf.Length)
			{
				this.ProcessWord(this.xBuf, 0);
				this.xBufOff = 0;
			}

			this.byteCount[0]++;
		}

		/// <inheritdoc/>
		public override void Update(byte[] input, int startIndex, int length)
		{
			//
			// fill the current word
			//
			while ((this.xBufOff != 0) && (length > 0))
			{
				this.Update(input[startIndex]);

				startIndex++;
				length--;
			}

			//
			// process whole words.
			//
			while (length > this.xBuf.Length)
			{
				this.ProcessWord(input, startIndex);

				startIndex += this.xBuf.Length;
				length -= this.xBuf.Length;
				this.byteCount[0] += this.xBuf.Length;
			}

			//
			// load in the remainder.
			//
			while (length > 0)
			{
				this.Update(input[startIndex]);

				startIndex++;
				length--;
			}
		}

		/// <inheritdoc/>
		public override int DoFinal(byte[] output, int startIndex)
		{
			if (output.Length - startIndex > this.DigestLength)
			{
				throw new ArgumentOutOfRangeException(nameof(startIndex), "Output array is insufficient to hold the hash value.");
			}

			this.Finish();

			Pack.UInt64_To_BE(this.H1, output, startIndex);
			Pack.UInt64_To_BE(this.H2, output, startIndex + 8);
			Pack.UInt64_To_BE(this.H3, output, startIndex + 16);
			Pack.UInt64_To_BE(this.H4, output, startIndex + 24);
			Pack.UInt64_To_BE(this.H5, output, startIndex + 32);
			Pack.UInt64_To_BE(this.H6, output, startIndex + 40);
			Pack.UInt64_To_BE(this.H7, output, startIndex + 48);
			Pack.UInt64_To_BE(this.H8, output, startIndex + 56);

			this.Reset();

			return this.DigestLength;
		}

		/// <inheritdoc/>
		public override byte[] ComputeHash(byte[] input, int startIndex, int length)
		{
			if (length > input.Length - startIndex)
			{
				throw new ArgumentOutOfRangeException(nameof(length), "Requested length can't exceed from remaining length of array after the start index.");
			}

			this.Update(input, startIndex, length);

			var output = new byte[this.DigestLength];

			this.Finish();

			Pack.UInt64_To_BE(this.H1, output, startIndex);
			Pack.UInt64_To_BE(this.H2, output, startIndex + 8);
			Pack.UInt64_To_BE(this.H3, output, startIndex + 16);
			Pack.UInt64_To_BE(this.H4, output, startIndex + 24);
			Pack.UInt64_To_BE(this.H5, output, startIndex + 32);
			Pack.UInt64_To_BE(this.H6, output, startIndex + 40);
			Pack.UInt64_To_BE(this.H7, output, startIndex + 48);
			Pack.UInt64_To_BE(this.H8, output, startIndex + 56);

			this.Reset();

			return output;
		}

		/// <inheritdoc/>
		public override IHash Clone()
		{
			return new SHA512();
		}

		#endregion Public
	}
}
