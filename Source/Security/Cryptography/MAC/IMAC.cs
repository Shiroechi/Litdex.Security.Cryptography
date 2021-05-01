using Litdex.Security.Cryptography.Hash;

namespace Litdex.Security.Cryptography.MAC
{
	/// <summary>
	///		The base interface for implementations of 
	///		message authentication codes (MACs).
	/// </summary>
	public interface IMAC
	{
		/// <summary>
		///		Initialise the MAC.
		/// </summary>
		/// <param name="key">
		///		Key required by the <see cref="MAC"/>.
		///	</param>
		void Initialize(byte[] key);

		/// <summary>
		///		Return the name of the algorithm the MAC implements.
		/// </summary>
		string AlgorithmName();

		/// <summary>
		///		Reset the MAC. At the end of resetting the MAC should be in the
		///		same state it was after the last init (if there was one).
		/// </summary>
		void Reset();

		/// <summary>
		///		Get used hash funtion in the MAC.
		/// </summary>
		/// <returns>
		///		The Hash function that this <see cref="MAC"/> use.
		/// </returns>
		IHash GetHashFunction();

		/// <summary>
		///		Return the size (in <see cref="byte"/>) of the hash value produced 
		///		by this hash function.
		/// </summary>
		/// <returns></returns>
		int GetHashLength();

		/// <summary>
		///		Update the HMAC value with a array of bytes.
		/// </summary>
		/// <param name="input">
		///		Input byte array to be hashed.
		///	</param>
		void Update(byte[] input);

		/// <summary>
		///		Computes the hash value for the specified input byte array.
		/// </summary>
		/// <param name="input">
		///		The input to compute the hash code for.
		///	</param>
		/// <param name="startIndex">
		///		The start index into the input byte array from which to begin using data.
		///	</param>
		/// <param name="length">
		///		The number of bytes in the array to use as data.
		///	</param>
		///	<exception cref="System.ArgumentOutOfRangeException">
		///		Requested length can't exceed from remaining length of array after the start index.
		/// </exception>
		void Update(byte[] input, int startIndex, int length);

		/// <summary>
		///		Copy final hash value and reset the hash function.
		/// </summary>
		/// <param name="output">
		///		The computed hash code.
		///	</param>
		/// <returns>
		///		Size of computed hash code.
		/// </returns>
		int DoFinal(byte[] output);

		/// <summary>
		///		Copy final hash value and reset the hash function.
		/// </summary>
		/// <param name="output">
		///		The computed hash code.
		///	</param>
		///	<param name="startIndex">
		///		The offset into the byte array from which to begin using data.
		/// </param>
		/// <returns>
		///		Size of computed hash code.
		/// </returns>
		int DoFinal(byte[] output, int startIndex);

		/// <summary>
		///		Computes the hash value for the specified region of the specified byte array.
		/// </summary>
		/// <param name="keys">
		///		MAC key.
		///	</param>
		///	<param name="input">
		///		Message to hash.
		/// </param>
		/// <returns>
		///		The computed hash code.
		/// </returns>
		byte[] ComputeHash(byte[] keys, byte[] input);
	}
}