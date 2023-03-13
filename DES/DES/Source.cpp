#include <iostream>
#include <string>
#include <bitset>
#include "DES.hpp"

using namespace std;


int main()
{
    string text = "02368ace";
    string key = "0f1571c94";
	string cipher = "";
    
	DES a;
	
	for (auto& byte : a.Encrypt(text, key))
	{
		cipher += a.BinaryBlockToString(byte);
	}

	for (auto& byte : a.Decrypt(cipher, key))
	{
		cout << a.BinaryBlockToString(byte);
	}

	cout << endl;
}