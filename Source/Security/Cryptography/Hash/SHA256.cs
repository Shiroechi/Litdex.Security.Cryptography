using System;

using Litdex.Utilities;
using Litdex.Utilities.Extension;

namespace Litdex.Security.Cryptography.Hash
{
	/// <summary>
	///		Implementation of SHA-2 256 bit.
	/// </summary>
	public class SHA256 : BaseSHA
	{
		#region Member

		private uint H1, H2, H3, H4, H5, H6, H7, H8;
		private readonly uint[] X = new uint[64];
		private int xOff;

		/// <summary>
		///		SHA-256 Constants.
		///		represent the first 32 bits 
		///		of the fractional parts of the 
		///		cube roots of the first sixty-four prime numbers.
		/// </summary>
		private readonly uint[] K =
		{
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
			0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
			0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
			0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
			0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
			0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
		};

		#endregion Member

		#region Constructor & Destructor

		/// <summary>
		///		Create an instance of <see cref="SHA256"/> object.
		/// </summary>
		public SHA256()
		{
			this.DigestLength = 32;
			this.InitializeHashValue();
		}

		/// <summary>
		///		Destructor.
		/// </summary>
		~SHA256()
		{
			this.Reset();
			this.K.Clear();
		}

		#endregion Constructor & Destructor

		#region Private Method

		/// <summary>
		///		SHA-256 initial hash value.
		///		The first 32 bits of the fractional parts of
		///		the square roots of the first eight prime numbers.
		/// </summary>
		private void InitializeHashValue()
		{
			this.H1 = 0x6a09e667;
			this.H2 = 0xbb67ae85;
			this.H3 = 0x3c6ef372;
			this.H4 = 0xa54ff53a;
			this.H5 = 0x510e527f;
			this.H6 = 0x9b05688c;
			this.H7 = 0x1f83d9ab;
			this.H8 = 0x5be0cd19;
		}

		internal override void ProcessWord(byte[] input, int inOff)
		{
			this.X[this.xOff] = Pack.BE_To_UInt32(input, inOff);

			if (++this.xOff == 16)
			{
				this.ProcessBlock();
			}
		}

		internal override void ProcessLength(long bitLength)
		{
			if (this.xOff > 14)
			{
				this.ProcessBlock();
			}

			this.X[14] = (uint)((ulong)bitLength >> 32);
			this.X[15] = (uint)((ulong)bitLength);
		}

		internal override void ProcessBlock()
		{
			//
			// expand 16 word block into 64 word blocks.
			//
			for (int ti = 16; ti <= 63; ti++)
			{
				this.X[ti] = this.Theta1(this.X[ti - 2]) + this.X[ti - 7] + this.Theta0(this.X[ti - 15]) + this.X[ti - 16];
			}

			//
			// set up working variables.
			//
			uint a = this.H1;
			uint b = this.H2;
			uint c = this.H3;
			uint d = this.H4;
			uint e = this.H5;
			uint f = this.H6;
			uint g = this.H7;
			uint h = this.H8;

			int t = 0;
			for (var i = 0; i < 8; ++i)
			{
				// t = 8 * i
				h += this.Sum1Ch(e, f, g) + this.K[t] + this.X[t];
				d += h;
				h += this.Sum0Maj(a, b, c);
				++t;

				// t = 8 * i + 1
				g += this.Sum1Ch(d, e, f) + this.K[t] + this.X[t];
				c += g;
				g += this.Sum0Maj(h, a, b);
				++t;

				// t = 8 * i + 2
				f += this.Sum1Ch(c, d, e) + this.K[t] + this.X[t];
				b += f;
				f += this.Sum0Maj(g, h, a);
				++t;

				// t = 8 * i + 3
				e += this.Sum1Ch(b, c, d) + this.K[t] + this.X[t];
				a += e;
				e += this.Sum0Maj(f, g, h);
				++t;

				// t = 8 * i + 4
				d += this.Sum1Ch(a, b, c) + this.K[t] + this.X[t];
				h += d;
				d += this.Sum0Maj(e, f, g);
				++t;

				// t = 8 * i + 5
				c += this.Sum1Ch(h, a, b) + this.K[t] + this.X[t];
				g += c;
				c += this.Sum0Maj(d, e, f);
				++t;

				// t = 8 * i + 6
				b += this.Sum1Ch(g, h, a) + this.K[t] + this.X[t];
				f += b;
				b += this.Sum0Maj(c, d, e);
				++t;

				// t = 8 * i + 7
				a += this.Sum1Ch(f, g, h) + this.K[t] + this.X[t];
				e += a;
				a += this.Sum0Maj(b, c, d);
				++t;
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
			this.xOff = 0;
			Array.Clear(this.X, 0, 16);
		}

		private uint Sum1Ch(uint x, uint y, uint z)
		{
			return (((x >> 6) | (x << 26)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 25) | (x << 7)))
				+ ((x & y) ^ ((~x) & z));
		}

		private uint Sum0Maj(uint x, uint y, uint z)
		{
			return (((x >> 2) | (x << 30)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 22) | (x << 10)))
				+ ((x & y) ^ (x & z) ^ (y & z));
		}

		private uint Theta0(uint x)
		{
			return ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3);
		}

		private uint Theta1(uint x)
		{
			return ((x >> 17) | (x << 15)) ^ ((x >> 19) | (x << 13)) ^ (x >> 10);
		}

		#endregion Private Method

		#region Public Method

		/// <inheritdoc/>
		public override string AlgorithmName()
		{
			return "SHA 2 - 256";
		}

		/// <inheritdoc/>
		public override void Reset()
		{
			base.Reset();

			this.InitializeHashValue();

			this.xOff = 0;
			Array.Clear(this.X, 0, this.X.Length);
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
		public override int DoFinal(byte[] output, int startIndex)
		{
			if (output.Length - startIndex > this.DigestLength)
			{
				throw new ArgumentOutOfRangeException(nameof(startIndex), "Output array is insufficient to hold the hash value.");
			}

			this.Finish();

			Pack.UInt32_To_BE(this.H1, output, startIndex);
			Pack.UInt32_To_BE(this.H2, output, startIndex + 4);
			Pack.UInt32_To_BE(this.H3, output, startIndex + 8);
			Pack.UInt32_To_BE(this.H4, output, startIndex + 12);
			Pack.UInt32_To_BE(this.H5, output, startIndex + 16);
			Pack.UInt32_To_BE(this.H6, output, startIndex + 20);
			Pack.UInt32_To_BE(this.H7, output, startIndex + 24);
			Pack.UInt32_To_BE(this.H8, output, startIndex + 28);

			this.Reset();

			return this.DigestLength;
		}

		/// <inheritdoc/>
		public override byte[] ComputeHash(byte[] input, int startIndex, int length)
		{
			this.Update(input, startIndex, input.Length);

			var output = new byte[this.DigestLength];
			this.Finish();

			Pack.UInt32_To_BE(this.H1, output, startIndex);
			Pack.UInt32_To_BE(this.H2, output, startIndex + 4);
			Pack.UInt32_To_BE(this.H3, output, startIndex + 8);
			Pack.UInt32_To_BE(this.H4, output, startIndex + 12);
			Pack.UInt32_To_BE(this.H5, output, startIndex + 16);
			Pack.UInt32_To_BE(this.H6, output, startIndex + 20);
			Pack.UInt32_To_BE(this.H7, output, startIndex + 24);
			Pack.UInt32_To_BE(this.H8, output, startIndex + 28);

			this.Reset();
			return output;
		}

		/// <inheritdoc/>
		public override IHash Clone()
		{
			return new SHA256();
		}

		#endregion Pubblic Method
	}
}