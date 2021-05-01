using System;

namespace Litdex.Security.Cryptography.Hash
{
	/// <summary>
	///		Implementation of Keccak based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
	/// </summary>
	/// <remarks>
	///		Following the naming conventions used in the C source code to enable easy review of the implementation.
	/// </remarks>
	public class Keccak : IHash
	{
		#region Member

		private static readonly ulong[] KeccakRoundConstants = KeccakInitializeRoundConstants();

		private static readonly int[] KeccakRhoOffsets = KeccakInitializeRhoOffsets();

		private static ulong[] KeccakInitializeRoundConstants()
		{
			ulong[] keccakRoundConstants = new ulong[24];
			byte LFSRState = 0x01;

			for (int i = 0; i < 24; i++)
			{
				keccakRoundConstants[i] = 0;
				for (int j = 0; j < 7; j++)
				{
					int bitPosition = (1 << j) - 1;

					// LFSR86540

					bool loBit = (LFSRState & 0x01) != 0;
					if (loBit)
					{
						keccakRoundConstants[i] ^= 1UL << bitPosition;
					}

					bool hiBit = (LFSRState & 0x80) != 0;
					LFSRState <<= 1;
					if (hiBit)
					{
						LFSRState ^= 0x71;
					}

				}
			}

			return keccakRoundConstants;
		}

		private static int[] KeccakInitializeRhoOffsets()
		{
			int[] keccakRhoOffsets = new int[25];
			int x, y, t, newX, newY;

			int rhoOffset = 0;
			keccakRhoOffsets[(((0) % 5) + 5 * ((0) % 5))] = rhoOffset;
			x = 1;
			y = 0;
			for (t = 1; t < 25; t++)
			{
				//rhoOffset = ((t + 1) * (t + 2) / 2) % 64;
				rhoOffset = (rhoOffset + t) & 63;
				keccakRhoOffsets[(((x) % 5) + 5 * ((y) % 5))] = rhoOffset;
				newX = (0 * x + 1 * y) % 5;
				newY = (2 * x + 3 * y) % 5;
				x = newX;
				y = newY;
			}

			return keccakRhoOffsets;
		}

		protected byte[] state = new byte[(1600 / 8)];
		protected byte[] dataQueue = new byte[(1536 / 8)];
		protected int rate;
		protected int bitsInQueue;
		protected int fixedOutputLength;
		protected bool squeezing;
		protected int bitsAvailableForSqueezing;
		protected byte[] chunk;
		protected byte[] oneByte;

		#endregion Member

		#region Constructor & Destructor

		/// <summary>
		///		Create an instance <see cref="Keccak"/> object.
		/// </summary>
		/// <param name="bitLength">
		///		Computed hash value length.
		/// </param>
		public Keccak(int bitLength = 512)
		{
			this.Init(bitLength);
		}

		~Keccak()
		{
			this.Reset();
			Array.Clear(this.state, 0, this.state.Length);
			Array.Clear(this.dataQueue, 0, this.dataQueue.Length);
			Array.Clear(this.chunk, 0, this.chunk.Length);
		}

		#endregion Constructor & Destructor

		#region Private Method

		private void ClearDataQueueSection(int off, int len)
		{
			for (var i = off; i != off + len; i++)
			{
				this.dataQueue[i] = 0;
			}
		}

		private void Init(int bitLength)
		{
			switch (bitLength)
			{
				case 128:
					this.InitSponge(1344, 256);
					break;
				case 224:
					this.InitSponge(1152, 448);
					break;
				case 256:
					this.InitSponge(1088, 512);
					break;
				case 288:
					this.InitSponge(1024, 576);
					break;
				case 384:
					this.InitSponge(832, 768);
					break;
				case 512:
					this.InitSponge(576, 1024);
					break;
				default:
					throw new ArgumentException("must be one of 128, 224, 256, 288, 384, or 512.", "bitLength");
			}
		}

		private void InitSponge(int rate, int capacity)
		{
			if (rate + capacity != 1600)
			{
				throw new InvalidOperationException("rate + capacity != 1600.");
			}

			if ((rate <= 0) || (rate >= 1600) || ((rate % 64) != 0))
			{
				throw new InvalidOperationException("Invalid rate value.");
			}

			this.rate = rate;
			this.fixedOutputLength = 0;
#if NET5_0_OR_GREATER
			Array.Fill<byte>(this.state, 0);
			Array.Fill<byte>(this.dataQueue, 0);
#elif NETSTANDARD2_0
			for (var i = 0; i < this.state.Length; i++)
			{
				this.state[i] = 0;
			}

			for (var i = 0; i < this.dataQueue.Length; i++)
			{
				this.dataQueue[i] = 0;
			}
#endif
			this.bitsInQueue = 0;
			this.squeezing = false;
			this.bitsAvailableForSqueezing = 0;
			this.fixedOutputLength = capacity / 2;
			this.chunk = new byte[rate / 8];
			this.oneByte = new byte[1];
		}

		private void AbsorbQueue()
		{
			this.KeccakAbsorb(this.state, this.dataQueue, this.rate / 8);

			this.bitsInQueue = 0;
		}

		protected virtual void Absorb(byte[] data, int off, long databitlen)
		{
			long i, j, wholeBlocks;

			if ((this.bitsInQueue % 8) != 0)
			{
				throw new InvalidOperationException("attempt to absorb with odd length queue.");
			}
			if (this.squeezing)
			{
				throw new InvalidOperationException("attempt to absorb while squeezing.");
			}

			i = 0;
			while (i < databitlen)
			{
				if ((this.bitsInQueue == 0) && (databitlen >= this.rate) && (i <= (databitlen - this.rate)))
				{
					wholeBlocks = (databitlen - i) / this.rate;

					for (j = 0; j < wholeBlocks; j++)
					{
						Array.Copy(data, (int)(off + (i / 8) + (j * this.chunk.Length)), this.chunk, 0, this.chunk.Length);

						this.KeccakAbsorb(this.state, this.chunk, this.chunk.Length);
					}

					i += wholeBlocks * this.rate;
				}
				else
				{
					int partialBlock = (int)(databitlen - i);
					if (partialBlock + this.bitsInQueue > this.rate)
					{
						partialBlock = this.rate - this.bitsInQueue;
					}
					int partialByte = partialBlock % 8;
					partialBlock -= partialByte;
					Array.Copy(data, off + (int)(i / 8), this.dataQueue, this.bitsInQueue / 8, partialBlock / 8);

					this.bitsInQueue += partialBlock;
					i += partialBlock;
					if (this.bitsInQueue == this.rate)
					{
						this.AbsorbQueue();
					}
					if (partialByte > 0)
					{
						int mask = (1 << partialByte) - 1;
						this.dataQueue[this.bitsInQueue / 8] = (byte)(data[off + ((int)(i / 8))] & mask);
						this.bitsInQueue += partialByte;
						i += partialByte;
					}
				}
			}
		}

		private void PadAndSwitchToSqueezingPhase()
		{
			if (this.bitsInQueue + 1 == this.rate)
			{
				this.dataQueue[this.bitsInQueue / 8] |= (byte)(1U << (this.bitsInQueue % 8));
				this.AbsorbQueue();
				this.ClearDataQueueSection(0, this.rate / 8);
			}
			else
			{
				this.ClearDataQueueSection((this.bitsInQueue + 7) / 8, this.rate / 8 - (this.bitsInQueue + 7) / 8);
				this.dataQueue[this.bitsInQueue / 8] |= (byte)(1U << (this.bitsInQueue % 8));
			}
			this.dataQueue[(this.rate - 1) / 8] |= (byte)(1U << ((this.rate - 1) % 8));
			this.AbsorbQueue();

			if (this.rate == 1024)
			{
				this.KeccakExtract1024bits(this.state, this.dataQueue);
				this.bitsAvailableForSqueezing = 1024;
			}
			else
			{
				this.KeccakExtract(this.state, this.dataQueue, this.rate / 64);
				this.bitsAvailableForSqueezing = this.rate;
			}

			this.squeezing = true;
		}

		protected virtual void Squeeze(byte[] output, int offset, long outputLength)
		{
			if (!this.squeezing)
			{
				this.PadAndSwitchToSqueezingPhase();
			}
			if ((outputLength % 8) != 0)
			{
				throw new InvalidOperationException("outputLength not a multiple of 8");
			}

			long i = 0;
			int partialBlock;

			while (i < outputLength)
			{
				if (this.bitsAvailableForSqueezing == 0)
				{
					this.KeccakPermutation(this.state);

					if (this.rate == 1024)
					{
						this.KeccakExtract1024bits(this.state, this.dataQueue);
						this.bitsAvailableForSqueezing = 1024;
					}
					else
					{
						this.KeccakExtract(this.state, this.dataQueue, this.rate / 64);
						this.bitsAvailableForSqueezing = this.rate;
					}
				}
				partialBlock = this.bitsAvailableForSqueezing;
				if (partialBlock > outputLength - i)
				{
					partialBlock = (int)(outputLength - i);
				}

				Array.Copy(this.dataQueue, (this.rate - this.bitsAvailableForSqueezing) / 8, output, offset + (int)(i / 8), partialBlock / 8);
				this.bitsAvailableForSqueezing -= partialBlock;
				i += partialBlock;
			}
		}

		private static void FromBytesToWords(ulong[] stateAsWords, byte[] state)
		{
			for (var i = 0; i < (1600 / 64); i++)
			{
				stateAsWords[i] = 0;
				var index = i * (64 / 8);
				for (var j = 0; j < (64 / 8); j++)
				{
					stateAsWords[i] |= ((ulong)state[index + j] & 0xff) << ((8 * j));
				}
			}
		}

		private static void FromWordsToBytes(byte[] state, ulong[] stateAsWords)
		{
			for (var i = 0; i < (1600 / 64); i++)
			{
				var index = i * (64 / 8);
				for (var j = 0; j < (64 / 8); j++)
				{
					state[index + j] = (byte)(stateAsWords[i] >> (8 * j));
				}
			}
		}

		private void KeccakPermutation(byte[] state)
		{
			var longState = new ulong[state.Length / 8];

			FromBytesToWords(longState, state);

			this.KeccakPermutationOnWords(longState);

			FromWordsToBytes(state, longState);
		}

		private void KeccakPermutationAfterXor(byte[] state, byte[] data, int dataLengthInBytes)
		{
			for (var i = 0; i < dataLengthInBytes; i++)
			{
				state[i] ^= data[i];
			}

			this.KeccakPermutation(state);
		}

		private void KeccakPermutationOnWords(ulong[] state)
		{
			for (var i = 0; i < 24; i++)
			{
				this.Theta(state);
				this.Rho(state);
				this.Pi(state);
				this.Chi(state);
				Iota(state, i);
			}
		}

		private readonly ulong[] C = new ulong[5];

		private void Theta(ulong[] A)
		{
			for (var x = 0; x < 5; x++)
			{
				this.C[x] = 0;
				for (var y = 0; y < 5; y++)
				{
					this.C[x] ^= A[x + 5 * y];
				}
			}
			for (var x = 0; x < 5; x++)
			{
				var dX = ((((this.C[(x + 1) % 5]) << 1) ^ ((this.C[(x + 1) % 5]) >> (64 - 1)))) ^ this.C[(x + 4) % 5];
				for (var y = 0; y < 5; y++)
				{
					A[x + 5 * y] ^= dX;
				}
			}
		}

		private void Rho(ulong[] A)
		{
			for (var x = 0; x < 5; x++)
			{
				for (var y = 0; y < 5; y++)
				{
					var index = x + 5 * y;
					A[index] = ((KeccakRhoOffsets[index] != 0) ? (((A[index]) << KeccakRhoOffsets[index]) ^ ((A[index]) >> (64 - KeccakRhoOffsets[index]))) : A[index]);
				}
			}
		}

		private readonly ulong[] tempA = new ulong[25];

		private void Pi(ulong[] A)
		{
			Array.Copy(A, 0, this.tempA, 0, this.tempA.Length);

			for (var x = 0; x < 5; x++)
			{
				for (var y = 0; y < 5; y++)
				{
					A[y + 5 * ((2 * x + 3 * y) % 5)] = this.tempA[x + 5 * y];
				}
			}
		}

		private readonly ulong[] chiC = new ulong[5];

		private void Chi(ulong[] A)
		{
			for (var y = 0; y < 5; y++)
			{
				for (var x = 0; x < 5; x++)
				{
					this.chiC[x] = A[x + 5 * y] ^ ((~A[(((x + 1) % 5) + 5 * y)]) & A[(((x + 2) % 5) + 5 * y)]);
				}
				for (var x = 0; x < 5; x++)
				{
					A[x + 5 * y] = this.chiC[x];
				}
			}
		}

		private static void Iota(ulong[] A, int indexRound)
		{
			A[(((0) % 5) + 5 * ((0) % 5))] ^= KeccakRoundConstants[indexRound];
		}

		private void KeccakAbsorb(byte[] byteState, byte[] data, int dataInBytes)
		{
			this.KeccakPermutationAfterXor(byteState, data, dataInBytes);
		}

		private void KeccakExtract1024bits(byte[] byteState, byte[] data)
		{
			Array.Copy(byteState, 0, data, 0, 128);
		}

		private void KeccakExtract(byte[] byteState, byte[] data, int laneCount)
		{
			Array.Copy(byteState, 0, data, 0, laneCount * 8);
		}

		#endregion Private Method

		#region Public Method

		/// <inheritdoc/>
		public virtual string AlgorithmName()
		{
			return "Keccak-" + this.fixedOutputLength;
		}

		/// <inheritdoc/>
		public virtual void Reset()
		{
			this.Init(this.fixedOutputLength);
		}

		/// <inheritdoc/>
		public virtual int GetHashLength()
		{
			return this.fixedOutputLength / 8;
		}

		/// <inheritdoc/>
		public virtual int GetByteLength()
		{
			return this.rate / 8;
		}

		/// <inheritdoc/>
		public virtual void Update(byte input)
		{
			this.oneByte[0] = input;

			this.Absorb(this.oneByte, 0, 8L);
		}

		/// <inheritdoc/>
		public virtual void Update(byte[] input)
		{
			this.Update(input, 0, input.Length);
		}

		/// <inheritdoc/>
		public virtual void Update(byte[] input, int startIndex, int length)
		{
			this.Absorb(input, startIndex, length * 8L);
		}

		/// <inheritdoc/>
		public virtual int DoFinal(byte[] output)
		{
			return this.DoFinal(output, 0);
		}

		/// <inheritdoc/>
		public virtual int DoFinal(byte[] output, int startIndex)
		{
			this.Squeeze(output, startIndex, this.fixedOutputLength);

			this.Reset();

			return this.GetHashLength();
		}

		/// <inheritdoc/>
		public virtual byte[] ComputeHash(byte[] input)
		{
			return this.ComputeHash(input, 0, input.Length);
		}

		/// <inheritdoc/>
		public virtual byte[] ComputeHash(byte[] input, int startIndex, int length)
		{
			var output = new byte[this.GetHashLength()];
			this.Update(input, startIndex, length);
			this.DoFinal(output, 0);
			return output;
		}

		/// <inheritdoc/>
		public virtual IHash Clone()
		{
			return new Keccak(this.fixedOutputLength);
		}

		#endregion Public Method
	}
}
