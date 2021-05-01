using System;

using Litdex.Utilities;

namespace Litdex.Security.Cryptography.Hash
{
	/// <summary>
	///		Implementation of SHA-1 as outlined in "Handbook of Applied Cryptography", pages 346 - 349. 
	///		It is interesting to ponder why the, apart from the extra IV, the other difference here from MD5
	///		is the "endianness" of the word processing!
	/// </summary>
	public class SHA1 : BaseSHA
	{
		#region Member

		private uint H1, H2, H3, H4, H5;

		private readonly uint[] X = new uint[80];
		private int xOff;

		//
		// Additive constants
		//
		private const uint Y1 = 0x5A827999;
		private const uint Y2 = 0x6ED9EBA1;
		private const uint Y3 = 0x8F1BBCDC;
		private const uint Y4 = 0xCA62C1D6;

		#endregion Member

		#region Constructor & Destructor

		/// <summary>
		///		Create an instance of <see cref="SHA1"/> object.
		/// </summary>
		public SHA1()
		{
			this.DigestLength = 20;
			this.Reset();
		}

		/// <summary>
		///		Destructor.
		/// </summary>
		~SHA1()
		{
			this.Reset();
		}

		#endregion Constructor & Destructor

		#region Private Method

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
			this.X[15] = (uint)(ulong)bitLength;
		}

		internal override void ProcessBlock()
		{
			//
			// expand 16 word block into 80 word block.
			//
			for (var i = 16; i < 80; i++)
			{
				uint t = this.X[i - 3] ^ this.X[i - 8] ^ this.X[i - 14] ^ this.X[i - 16];
				this.X[i] = t << 1 | t >> 31;
			}

			//
			// set up working variables.
			//
			uint A = this.H1;
			uint B = this.H2;
			uint C = this.H3;
			uint D = this.H4;
			uint E = this.H5;

			//
			// round 1
			//
			var idx = 0;

			for (var j = 0; j < 4; j++)
			{
				// E = rotateLeft(A, 5) + F(B, C, D) + E + X[idx++] + Y1
				// B = rotateLeft(B, 30)
				E += (A << 5 | (A >> 27)) + this.F(B, C, D) + this.X[idx++] + Y1;
				B = B << 30 | (B >> 2);

				D += (E << 5 | (E >> 27)) + this.F(A, B, C) + this.X[idx++] + Y1;
				A = A << 30 | (A >> 2);

				C += (D << 5 | (D >> 27)) + this.F(E, A, B) + this.X[idx++] + Y1;
				E = E << 30 | (E >> 2);

				B += (C << 5 | (C >> 27)) + this.F(D, E, A) + this.X[idx++] + Y1;
				D = D << 30 | (D >> 2);

				A += (B << 5 | (B >> 27)) + this.F(C, D, E) + this.X[idx++] + Y1;
				C = C << 30 | (C >> 2);
			}

			//
			// round 2
			//
			for (var j = 0; j < 4; j++)
			{
				// E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y2
				// B = rotateLeft(B, 30)
				E += (A << 5 | (A >> 27)) + this.H(B, C, D) + this.X[idx++] + Y2;
				B = B << 30 | (B >> 2);

				D += (E << 5 | (E >> 27)) + this.H(A, B, C) + this.X[idx++] + Y2;
				A = A << 30 | (A >> 2);

				C += (D << 5 | (D >> 27)) + this.H(E, A, B) + this.X[idx++] + Y2;
				E = E << 30 | (E >> 2);

				B += (C << 5 | (C >> 27)) + this.H(D, E, A) + this.X[idx++] + Y2;
				D = D << 30 | (D >> 2);

				A += (B << 5 | (B >> 27)) + this.H(C, D, E) + this.X[idx++] + Y2;
				C = C << 30 | (C >> 2);
			}

			//
			// round 3
			//
			for (var j = 0; j < 4; j++)
			{
				// E = rotateLeft(A, 5) + G(B, C, D) + E + X[idx++] + Y3
				// B = rotateLeft(B, 30)
				E += (A << 5 | (A >> 27)) + this.G(B, C, D) + this.X[idx++] + Y3;
				B = B << 30 | (B >> 2);

				D += (E << 5 | (E >> 27)) + this.G(A, B, C) + this.X[idx++] + Y3;
				A = A << 30 | (A >> 2);

				C += (D << 5 | (D >> 27)) + this.G(E, A, B) + this.X[idx++] + Y3;
				E = E << 30 | (E >> 2);

				B += (C << 5 | (C >> 27)) + this.G(D, E, A) + this.X[idx++] + Y3;
				D = D << 30 | (D >> 2);

				A += (B << 5 | (B >> 27)) + this.G(C, D, E) + this.X[idx++] + Y3;
				C = C << 30 | (C >> 2);
			}

			//
			// round 4
			//
			for (var j = 0; j < 4; j++)
			{
				// E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y4
				// B = rotateLeft(B, 30)
				E += (A << 5 | (A >> 27)) + this.H(B, C, D) + this.X[idx++] + Y4;
				B = B << 30 | (B >> 2);

				D += (E << 5 | (E >> 27)) + this.H(A, B, C) + this.X[idx++] + Y4;
				A = A << 30 | (A >> 2);

				C += (D << 5 | (D >> 27)) + this.H(E, A, B) + this.X[idx++] + Y4;
				E = E << 30 | (E >> 2);

				B += (C << 5 | (C >> 27)) + this.H(D, E, A) + this.X[idx++] + Y4;
				D = D << 30 | (D >> 2);

				A += (B << 5 | (B >> 27)) + this.H(C, D, E) + this.X[idx++] + Y4;
				C = C << 30 | (C >> 2);
			}

			this.H1 += A;
			this.H2 += B;
			this.H3 += C;
			this.H4 += D;
			this.H5 += E;

			//
			// reset start of the buffer.
			//
			this.xOff = 0;
			Array.Clear(this.X, 0, 16);
		}

		private uint F(uint u, uint v, uint w)
		{
			return (u & v) | (~u & w);
		}

		private uint H(uint u, uint v, uint w)
		{
			return u ^ v ^ w;
		}

		private uint G(uint u, uint v, uint w)
		{
			return (u & v) | (u & w) | (v & w);
		}

		#endregion Private Method

		#region Public

		/// <inheritdoc/>
		public override string AlgorithmName()
		{
			return "SHA-1";
		}

		/// <inheritdoc/>
		public override void Reset()
		{
			base.Reset();

			this.H1 = 0x67452301;
			this.H2 = 0xefcdab89;
			this.H3 = 0x98badcfe;
			this.H4 = 0x10325476;
			this.H5 = 0xc3d2e1f0;

			this.xOff = 0;
			Array.Clear(this.X, 0, this.X.Length);
		}

		/// <inheritdoc/>
		public override int GetHashLength()
		{
			return this.DigestLength;
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

			this.Finish();

			var output = new byte[this.DigestLength];

			Pack.UInt32_To_BE(this.H1, output, 0);
			Pack.UInt32_To_BE(this.H2, output, 4);
			Pack.UInt32_To_BE(this.H3, output, 8);
			Pack.UInt32_To_BE(this.H4, output, 12);
			Pack.UInt32_To_BE(this.H5, output, 16);

			this.Reset();

			return output;
		}

		/// <inheritdoc/>
		public override IHash Clone()
		{
			return new SHA1();
		}

		#endregion Public	
	}
}