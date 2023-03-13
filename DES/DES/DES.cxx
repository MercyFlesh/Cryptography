#include "DES.hpp"

using namespace std;

vector<bitset<64>> DES::Encrypt(const string& text, const string& key)
{
	vector<bitset<64>> resultBitsBlocks;
	bitset<64> bitKey = StringToBinaryBlock(key);
	vector<bitset<48>> roundKeys = GenerateKeys(bitKey);

	for (size_t i = 0; i < text.size(); i += 8)
	{
		bitset<64> bitsBlock = StringToBinaryBlock(text.substr(i, i + 8));
		bitset<64> permuatationBlock;
		for (size_t j = 0; j < bitsBlock.size(); j++)
			permuatationBlock[bitsBlock.size() - j - 1] = bitsBlock[bitsBlock.size() - _initialPermutationTable[j]];
		
		bitset<32> left, right, tempLeft;
		for (size_t j = 0; j < permuatationBlock.size() / 2; j++)
		{
			right[j] = permuatationBlock[j];
			left[j] = permuatationBlock[j + right.size()];
		}

		for (int j = 0; j < 16; j++)
		{
			tempLeft = right;
			right = left ^	FeistelCipher(right, roundKeys[j]);
			left = tempLeft;
		}

		bitset<64> resultBlock;
		for (size_t j = 0; j < left.size(); j++)
		{
			resultBlock[j] = left[j];
			resultBlock[j + left.size()] = right[j];
		}

		permuatationBlock = resultBlock;
		for (size_t j = 0; j < resultBlock.size(); j++)
			resultBlock[resultBlock.size() - j - 1] = permuatationBlock[resultBlock.size() - _inversionPermutationTable[j]];

		resultBitsBlocks.emplace_back(resultBlock);
	}

	return resultBitsBlocks;
}

vector<bitset<64>> DES::Decrypt(const string& text, const string& key)
{
	vector<bitset<64>> resultBitsBlocks;
	bitset<64> bitKey = StringToBinaryBlock(key);
	vector<bitset<48>> roundKeys = GenerateKeys(bitKey);

	for (size_t i = 0; i < text.size(); i += 8)
	{
		bitset<64> bitsBlock = StringToBinaryBlock(text.substr(i, i + 8));
		bitset<64> permuatationBlock;
		for (size_t j = 0; j < bitsBlock.size(); j++)
			permuatationBlock[bitsBlock.size() - j - 1] = bitsBlock[bitsBlock.size() - _initialPermutationTable[j]];

		bitset<32> left, right, tempLeft;
		for (size_t j = 0; j < permuatationBlock.size() / 2; j++)
		{
			right[j] = permuatationBlock[j];
			left[j] = permuatationBlock[j + right.size()];
		}

		for (int j = 0; j < 16; j++)
		{
			tempLeft = right;
			right = left ^ FeistelCipher(right, roundKeys[15 - j]);
			left = tempLeft;
		}

		bitset<64> resultBlock;
		for (size_t j = 0; j < left.size(); j++)
		{
			resultBlock[j] = left[j];
			resultBlock[j + left.size()] = right[j];
		}

		permuatationBlock = resultBlock;
		for (size_t j = 0; j < resultBlock.size(); j++)
			resultBlock[resultBlock.size() - j - 1] = permuatationBlock[resultBlock.size() - _inversionPermutationTable[j]];

		resultBitsBlocks.emplace_back(resultBlock);
	}

	return resultBitsBlocks;
}

bitset<32> DES::FeistelCipher(const bitset<32>& rightBlock, const bitset<48>& key)
{
	bitset<48> expandedBlock;
	for (size_t i = 0; i < expandedBlock.size(); i++)
		expandedBlock[expandedBlock.size() - i - 1] = rightBlock[rightBlock.size() - _expansionTable[i]];

	expandedBlock = expandedBlock ^ key;

	bitset<32> result;
	for (size_t i = 0, j = 0; i < expandedBlock.size(); i += 6, j += 4)
	{
		int row = expandedBlock[expandedBlock.size() - i - 1] * 2 + expandedBlock[expandedBlock.size() - i - 1 - 5];
		int col = expandedBlock[expandedBlock.size() - i - 2] * 8 +
			expandedBlock[expandedBlock.size() - i - 3] * 4 +
			expandedBlock[expandedBlock.size() - i - 4] * 2 +
			expandedBlock[expandedBlock.size() - i - 5];

		int val = _substitionBoxes[i / 6][row][col];
		bitset<4> binary(val);
		result[31 - j] = binary[3];
		result[31 - j - 1] = binary[2];
		result[31 - j - 2] = binary[1];
		result[31 - j - 3] = binary[0];
	}

	bitset<32> temp = result;
	for (size_t i = 0; i < result.size(); ++i)
		result[result.size() - i - 1] = temp[result.size() - _permutationTable[i]];

	return result;
}

vector<bitset<48>> DES::GenerateKeys(const bitset<64>& key)
{
	const int rounds = 16;
	vector<bitset<48>> keys(rounds);
	
	bitset<56> permKey;
	for (int i = 0; i < 56; ++i)
		permKey[55 - i] = key[64 - PC1[i]];
	
	bitset<28> left, right;
	for (int i = 0; i < rounds; i++)
	{
		for (size_t j = 0; j < permKey.size() / 2; j++)
		{
			right[j] = permKey[j];
			left[j] = permKey[j + right.size()];
		}

		LeftShift(left, _roundShift[i]);
		LeftShift(right, _roundShift[i]);

		for (size_t j = 0; j < right.size(); j++)
		{
			permKey[j] = right[j];
			permKey[j + right.size()] = left[j];
		}
			
		bitset<48> roundKey;
		for (int j = 0; j < 48; j++)
			roundKey[47 - j] = permKey[56 - PC2[j]];

		keys[i] = roundKey;
	}

	return keys;
}

bitset<64> DES::StringToBinaryBlock(const string& str)
{
	bitset<64> bits;
	for (size_t i = 0; i < str.size() && i * 8 < bits.size(); ++i)
		for (size_t j = 0; j < 8; ++j)
			bits[i * 8 + j] = ((str[i] >> j) & 1);

	return bits;
}

string DES::BinaryBlockToString(const bitset<64>& characters) 
{
	string result;
	for (int i = 0; i < 8; ++i) 
	{
		char c = 0x00;
		for (int j = 7; j >= 0; j--) {
			c = c + characters[i * 8 + j];
			if (j != 0) 
				c = c * 2;
		}

		result += c;
	}

	return result;
}

void DES::LeftShift(bitset<28>& keyBatch, int shift)
{
	bitset<28> temp = keyBatch;
	for (int i = keyBatch.size() - 1; i >= 0; --i)
	{
		if (i - shift < 0)
			keyBatch[i] = temp[i - shift + keyBatch.size()];
		else
			keyBatch[i] = temp[i - shift];
	}
}
