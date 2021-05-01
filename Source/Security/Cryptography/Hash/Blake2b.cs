using System;

using Litdex.Utilities;

namespace Litdex.Security.Cryptography.Hash
{
	/// <summary>
	///		Implementation of the cryptographic hash function Blakbe2b.
	/// 
	///		Blake2b offers a built-in keying mechanism to be used directly
	///		for authentication ("Prefix-MAC") rather than a HMAC construction.
	/// 
	///		Blake2b offers a built-in support for a salt for randomized hashing
	///		and a personal string for defining a unique hash function for each application.
	/// 
	///		BLAKE2b is optimized for 64-bit platforms and produces digests of any 
	///		between 1 and 64 bytes.
	/// </summary>
	public class Blake2b : IHash
	{
		#region Member

		private const int ROUNDS = 12; // to use for Catenas H'
		private const int BLOCK_LENGTH_BYTES = 128;// bytes

		// General parameters:
		private readonly int digestLength = 64; // 1 - 64 bytes
		private readonly int keyLength = 0; // 0 - 64 bytes for keyed hashing for MAC
		private readonly byte[] salt = null; // new byte[16];
		private readonly byte[] personalization = null; // new byte[16];

		/// <summary>
		///		Key
		/// </summary>
		private readonly byte[] key = null;

		// whenever this buffer overflows, it will be processed
		// in the Compress() function.
		// For performance issues, long messages will not use this buffer.
		private readonly byte[] buffer = null;// new byte[BLOCK_LENGTH_BYTES];
											  // Position of last inserted byte:
		private int bufferPos = 0;// a value from 0 up to 128

		private readonly ulong[] internalState = new ulong[16]; // In the Blake2b paper it is
																// called: v
		private ulong[] chainValue = null; // state vector, in the Blake2b paper it
										   // is called: h

		private ulong t0 = 0UL; // holds last significant bits, counter (counts bytes)
		private ulong t1 = 0UL; // counter: Length up to 2^128 are supported
		private ulong f0 = 0UL; // finalization flag, for last block: ~0L

		// Blake2b Initialization Vector:
		// Produced from the square root of primes 2, 3, 5, 7, 11, 13, 17, 19.
		// The same as SHA-512 IV.
		private readonly ulong[] blake2b_IV =
			{
				0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL,
				0xa54ff53a5f1d36f1UL, 0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
				0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
			};

		// Message word permutations:
		private readonly byte[,] blake2b_sigma =
		{
			{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
			{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
			{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
			{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
			{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
			{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
			{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
			{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
			{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
			{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
			{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
			{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
		};

		#endregion Member

		/// <summary>
		///		Create an instance of <see cref="Blake2b"/> object.
		/// </summary>
		/// <param name="digestSize">
		///		Size of hash values in bits.
		///	</param>
		public Blake2b(int digestSize = 512)
		{
			if (digestSize != 160 && digestSize != 256 && digestSize != 384 && digestSize != 512)
			{
				throw new ArgumentException("BLAKE2b hash function restricted to one of [160, 256, 384, 512] bits only.");
			}

			this.buffer = new byte[BLOCK_LENGTH_BYTES];
			this.keyLength = 0;
			this.digestLength = digestSize / 8;
			this.Init();
		}

		/// <summary>
		///		Blake2b for authentication ("Prefix-MAC mode").
		/// </summary>
		/// <param name="key">
		///		A key up to 64 bytes or null.
		///	</param>
		public Blake2b(byte[] key)
		{
			this.buffer = new byte[BLOCK_LENGTH_BYTES];
			if (key != null)
			{
				this.key = new byte[key.Length];
				Array.Copy(key, 0, this.key, 0, key.Length);

				if (key.Length > 64)
				{
					throw new ArgumentException("Keys > 64 are not supported.");
				}

				this.keyLength = key.Length;
				Array.Copy(key, 0, this.buffer, 0, key.Length);
				this.bufferPos = BLOCK_LENGTH_BYTES; // zero padding
			}
			this.digestLength = 64;
			this.Init();
		}

		/// <summary>
		///		Blake2b with key, required digest length (in bytes), salt and personalization.
		/// </summary>
		/// <param name="key">
		///		A key up to 64 bytes or null.
		///	</param>
		/// <param name="digestLength">
		///		From 1 up to 64 bytes.
		///	</param>
		/// <param name="salt">
		///		16 bytes or null.
		///	</param>
		/// <param name="personalization">
		///		16 bytes or null.
		///	</param>
		public Blake2b(byte[] key, int digestLength, byte[] salt, byte[] personalization)
		{
			if (digestLength < 1 || digestLength > 64)
			{
				throw new ArgumentException("Invalid digest length (required: 1 - 64)");
			}

			this.digestLength = digestLength;
			this.buffer = new byte[BLOCK_LENGTH_BYTES];

			if (salt != null)
			{
				if (salt.Length != 16)
				{
					throw new ArgumentException("salt length must be exactly 16 bytes");
				}

				this.salt = new byte[16];
				Array.Copy(salt, 0, this.salt, 0, salt.Length);
			}

			if (personalization != null)
			{
				if (personalization.Length != 16)
				{
					throw new ArgumentException("personalization length must be exactly 16 bytes");
				}

				this.personalization = new byte[16];
				Array.Copy(personalization, 0, this.personalization, 0, personalization.Length);
			}

			if (key != null)
			{
				if (key.Length > 64)
				{
					throw new ArgumentException("Keys > 64 are not supported");
				}

				this.key = new byte[key.Length];
				Array.Copy(key, 0, this.key, 0, key.Length);

				this.keyLength = key.Length;
				Array.Copy(key, 0, this.buffer, 0, key.Length);
				this.bufferPos = BLOCK_LENGTH_BYTES; // zero padding
			}

			this.Init();
		}

		/// <summary>
		///		Destructor.
		/// </summary>
		~Blake2b()
		{
			this.ClearKey();
			this.ClearSalt();
			this.Reset();
		}

		#region Private Method

		/// <summary>
		///		Initialize chainValue
		/// </summary>
		private void Init()
		{
			if (this.chainValue == null)
			{
				this.chainValue = new ulong[8];

				this.chainValue[0] = this.blake2b_IV[0] ^ (ulong)(this.digestLength | (this.keyLength << 8) | 0x1010000);

				this.chainValue[1] = this.blake2b_IV[1];
				this.chainValue[2] = this.blake2b_IV[2];
				this.chainValue[3] = this.blake2b_IV[3];
				this.chainValue[4] = this.blake2b_IV[4];
				this.chainValue[5] = this.blake2b_IV[5];

				if (this.salt != null)
				{
					this.chainValue[4] ^= Pack.LE_To_UInt64(this.salt, 0);
					this.chainValue[5] ^= Pack.LE_To_UInt64(this.salt, 8);
				}

				this.chainValue[6] = this.blake2b_IV[6];
				this.chainValue[7] = this.blake2b_IV[7];

				if (this.personalization != null)
				{
					this.chainValue[6] ^= Pack.LE_To_UInt64(this.personalization, 0);
					this.chainValue[7] ^= Pack.LE_To_UInt64(this.personalization, 8);
				}
			}
		}

		private void InitializeInternalState()
		{
			// initialize v:
			Array.Copy(this.chainValue, 0, this.internalState, 0, this.chainValue.Length);
			Array.Copy(this.blake2b_IV, 0, this.internalState, this.chainValue.Length, 4);
			this.internalState[12] = this.t0 ^ this.blake2b_IV[4];
			this.internalState[13] = this.t1 ^ this.blake2b_IV[5];
			this.internalState[14] = this.f0 ^ this.blake2b_IV[6];
			this.internalState[15] = this.blake2b_IV[7];// ^ f1 with f1 = 0
		}

		private void Compress(byte[] message, int messagePos)
		{
			this.InitializeInternalState();

			ulong[] m = new ulong[16];
			for (int j = 0; j < 16; j++)
			{
				m[j] = Pack.LE_To_UInt64(message, messagePos + j * 8);
			}

			for (int round = 0; round < ROUNDS; round++)
			{
				// G apply to columns of internalState:m[blake2b_sigma[round][2 * blockPos]] /+1
				this.G(m[this.blake2b_sigma[round, 0]], m[this.blake2b_sigma[round, 1]], 0, 4, 8, 12);
				this.G(m[this.blake2b_sigma[round, 2]], m[this.blake2b_sigma[round, 3]], 1, 5, 9, 13);
				this.G(m[this.blake2b_sigma[round, 4]], m[this.blake2b_sigma[round, 5]], 2, 6, 10, 14);
				this.G(m[this.blake2b_sigma[round, 6]], m[this.blake2b_sigma[round, 7]], 3, 7, 11, 15);

				// G apply to diagonals of internalState:
				this.G(m[this.blake2b_sigma[round, 8]], m[this.blake2b_sigma[round, 9]], 0, 5, 10, 15);
				this.G(m[this.blake2b_sigma[round, 10]], m[this.blake2b_sigma[round, 11]], 1, 6, 11, 12);
				this.G(m[this.blake2b_sigma[round, 12]], m[this.blake2b_sigma[round, 13]], 2, 7, 8, 13);
				this.G(m[this.blake2b_sigma[round, 14]], m[this.blake2b_sigma[round, 15]], 3, 4, 9, 14);
			}

			// update chain values:
			for (int offset = 0; offset < this.chainValue.Length; offset++)
			{
				this.chainValue[offset] = this.chainValue[offset] ^ this.internalState[offset] ^ this.internalState[offset + 8];
			}
		}

		private void G(ulong m1, ulong m2, int posA, int posB, int posC, int posD)
		{
			this.internalState[posA] = this.internalState[posA] + this.internalState[posB] + m1;
			this.internalState[posD] = this.Rotr64(this.internalState[posD] ^ this.internalState[posA], 32);
			this.internalState[posC] = this.internalState[posC] + this.internalState[posD];
			this.internalState[posB] = this.Rotr64(this.internalState[posB] ^ this.internalState[posC], 24); // replaces 25 of BLAKE
			this.internalState[posA] = this.internalState[posA] + this.internalState[posB] + m2;
			this.internalState[posD] = this.Rotr64(this.internalState[posD] ^ this.internalState[posA], 16);
			this.internalState[posC] = this.internalState[posC] + this.internalState[posD];
			this.internalState[posB] = this.Rotr64(this.internalState[posB] ^ this.internalState[posC], 63); // replaces 11 of BLAKE
		}

		private ulong Rotr64(ulong x, int rot)
		{
			return x >> rot | x << -rot;
		}

		#endregion Private Method

		#region Public Method

		/// <inheritdoc/>
		public string AlgorithmName()
		{
			return "Blake2b - " + (this.digestLength * 8);
		}

		/// <inheritdoc/>
		public void Reset()
		{
			this.bufferPos = 0;
			this.f0 = 0L;
			this.t0 = 0L;
			this.t1 = 0L;
			this.chainValue = null;
			Array.Clear(this.buffer, 0, this.buffer.Length);
			if (this.key != null)
			{
				Array.Copy(this.key, 0, this.buffer, 0, this.key.Length);
				this.bufferPos = BLOCK_LENGTH_BYTES; // zero padding
			}
			this.Init();
		}

		/// <inheritdoc/>
		public int GetHashLength()
		{
			return this.digestLength;
		}

		/// <inheritdoc/>
		public int GetByteLength()
		{
			return BLOCK_LENGTH_BYTES;
		}

		/// <summary>
		///	 Overwrite the key if it is no longer used (zeroization).
		/// </summary>
		public virtual void ClearKey()
		{
			if (this.key != null)
			{
				Array.Clear(this.key, 0, this.key.Length);
				Array.Clear(this.buffer, 0, this.buffer.Length);
			}
		}

		/// <summary>
		///		Overwrite the salt (pepper) if it is secret and no longer used (zeroization).
		/// </summary>
		public virtual void ClearSalt()
		{
			if (this.salt != null)
			{
				Array.Clear(this.salt, 0, this.salt.Length);
			}
		}

		/// <inheritdoc/>
		public void Update(byte input)
		{
			int remainingLength = 0; // left bytes of buffer

			// process the buffer if full else add to buffer:
			remainingLength = BLOCK_LENGTH_BYTES - this.bufferPos;
			if (remainingLength == 0)
			{
				// full buffer
				this.t0 += BLOCK_LENGTH_BYTES;
				if (this.t0 == 0)
				{
					// if message > 2^64
					this.t1++;
				}

				this.Compress(this.buffer, 0);
				Array.Clear(this.buffer, 0, this.buffer.Length);// clear buffer
				this.buffer[0] = input;
				this.bufferPos = 1;
			}
			else
			{
				this.buffer[this.bufferPos] = input;
				this.bufferPos++;
				return;
			}
		}

		/// <inheritdoc/>
		public void Update(byte[] input)
		{
			this.Update(input, 0, input.Length);
		}

		/// <inheritdoc/>
		public void Update(byte[] input, int startIndex, int length)
		{
			if (input == null || length == 0)
			{
				return;
			}

			int remainingLength = 0; // left bytes of buffer

			if (this.bufferPos != 0)
			{
				// commenced, incomplete buffer

				// complete the buffer:
				remainingLength = BLOCK_LENGTH_BYTES - this.bufferPos;
				if (remainingLength < length)
				{
					// full buffer + at least 1 byte
					Array.Copy(input, startIndex, this.buffer, this.bufferPos, remainingLength);
					this.t0 += BLOCK_LENGTH_BYTES;
					if (this.t0 == 0)
					{
						// if message > 2^64
						this.t1++;
					}

					this.Compress(this.buffer, 0);
					this.bufferPos = 0;
					Array.Clear(this.buffer, 0, this.buffer.Length);// clear buffer
				}
				else
				{
					Array.Copy(input, startIndex, this.buffer, this.bufferPos, length);
					this.bufferPos += length;
					return;
				}
			}

			// process blocks except last block (also if last block is full)
			int messagePos;
			int blockWiseLastPos = startIndex + length - BLOCK_LENGTH_BYTES;
			for (messagePos = startIndex + remainingLength; messagePos < blockWiseLastPos; messagePos += BLOCK_LENGTH_BYTES)
			{
				// block wise 128 bytes
				// without buffer:
				this.t0 += BLOCK_LENGTH_BYTES;
				if (this.t0 == 0)
				{
					this.t1++;
				}
				this.Compress(input, messagePos);
			}

			// fill the buffer with left bytes, this might be a full block
			Array.Copy(input, messagePos, this.buffer, 0, startIndex + length - messagePos);
			this.bufferPos += startIndex + length - messagePos;
		}

		/// <inheritdoc/>
		public int DoFinal(byte[] output)
		{
			return this.DoFinal(output, 0);
		}

		/// <inheritdoc/>
		public int DoFinal(byte[] output, int startIndex)
		{
			this.f0 = 0xFFFFFFFFFFFFFFFFUL;
			this.t0 += (ulong)this.bufferPos;
			if (this.bufferPos > 0 && this.t0 == 0)
			{
				this.t1++;
			}

			this.Compress(this.buffer, 0);
			Array.Clear(this.buffer, 0, this.buffer.Length);// Holds eventually the key if input is null
			Array.Clear(this.internalState, 0, this.internalState.Length);

			for (int i = 0; i < this.chainValue.Length && (i * 8 < this.digestLength); i++)
			{
				byte[] bytes = Pack.UInt64_To_LE(this.chainValue[i]);

				if (i * 8 < this.digestLength - 8)
				{
					Array.Copy(bytes, 0, output, startIndex + i * 8, 8);
				}
				else
				{
					Array.Copy(bytes, 0, output, startIndex + i * 8, this.digestLength - (i * 8));
				}
			}

			Array.Clear(this.chainValue, 0, this.chainValue.Length);

			this.Reset();

			return this.digestLength;
		}

		/// <inheritdoc/>
		public byte[] ComputeHash(byte[] input)
		{
			return this.ComputeHash(input, 0, input.Length);
		}

		/// <inheritdoc/>
		public byte[] ComputeHash(byte[] input, int startIndex, int length)
		{
			byte[] result = new byte[this.digestLength];
			this.Update(input, startIndex, length);
			this.DoFinal(result, 0);
			return result;
		}

		/// <inheritdoc/>
		public IHash Clone()
		{
			return new Blake2b(this.digestLength);
		}

		#endregion Public
	}
}
