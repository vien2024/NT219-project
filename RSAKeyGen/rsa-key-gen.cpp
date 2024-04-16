// Linux help: http://www.cryptopp.com/wiki/Linux

// Standard C/C++

#include <iostream>
using std::cout;
using std::cin;
using std::cerr;
using std::endl;

// Vietnamese support
#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdlib>
#include <locale>
#include <cctype>

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

/*Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;

#include <cryptopp/modarith.h>
using CryptoPP::ModularArithmetic;;

#include "cryptopp\hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

//CryptoPP
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/dsa.h"
using CryptoPP::DSA;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_PKCS1v15_Decryptor;
using CryptoPP::RSAES_PKCS1v15_Encryptor;
using CryptoPP::InvertibleRSAFunction;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include <cryptopp/cryptlib.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::DecodingResult;
using CryptoPP::BufferedTransformation;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::BufferedTransformation;
using CryptoPP::PK_EncryptorFilter; // Public key encryption
using CryptoPP::PK_DecryptorFilter; // Public key decryption

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <sstream>
using std::ostringstream;

string integer_to_hex(const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << std::hex << t;
    std::string encoded(oss.str());
    return encoded;
}

void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key);
void SaveBase64PublicKey(const string& filename, const PublicKey& key);

void SaveBase64(const string& filename, const BufferedTransformation& bt);
void Save(const string& filename, const BufferedTransformation& bt);

void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);

void LoadBase64PrivateKey(const string& filename, PrivateKey& key);
void LoadBase64PublicKey(const string& filename, PublicKey& key);

void LoadBase64(const string& filename, BufferedTransformation& bt);
void Load(const string& filename, BufferedTransformation& bt);

int main(int argc, char** argv)
{
	// Set locale to support UTF-8
    #ifdef __linux__
    std::locale::global(std::locale("C.utf8"));
    #endif
    #ifdef _WIN32
    // Set console code page to UTF-8 on Windows C.utf8, CP_UTF8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif
	std::ios_base::sync_with_stdio(false);

	
	AutoSeededRandomPool rng;


	RSA::PrivateKey rsaPrivate;
	rsaPrivate.GenerateRandomWithKeySize(rng, 3072);

	RSA::PublicKey rsaPublic(rsaPrivate);
	rsaPublic.SetPublicExponent(65537);
	SavePrivateKey("rsa-private.key", rsaPrivate); // save in der or binary format
	SavePublicKey("rsa-public.key", rsaPublic); // save in der or binary format

	RSA::PrivateKey r1, r2;
	r1.GenerateRandomWithKeySize(rng, 3072);

	SavePrivateKey("rsa-roundtrip.key", r1);
	LoadPrivateKey("rsa-roundtrip.key", r2);
	
	r1.Validate(rng, 3);
	r2.Validate(rng, 3);

	if(r1.GetModulus() != r2.GetModulus() ||
		r1.GetPublicExponent() != r2.GetPublicExponent() ||
		r1.GetPrivateExponent() != r2.GetPrivateExponent())
	{
		throw runtime_error("key data did not round trip");
	}
	
	cout << "Successfully generated and saved RSA keys" << endl;

	// Load key from file

	LoadPrivateKey("rsa-private.key", rsaPrivate);
	LoadPublicKey("rsa-public.key", rsaPublic);
	// Get system parameters
	CryptoPP::Integer modul1 = rsaPrivate.GetModulus(); // modul n
	CryptoPP::Integer prime1 = rsaPrivate.GetPrime1(); // prime p
	CryptoPP::Integer prime2 = rsaPrivate.GetPrime2();  // prime q

	/* Secret exponent d; public exponent e */
	CryptoPP::Integer SK = rsaPrivate.GetPrivateExponent(); // secret exponent d; 
	CryptoPP::Integer PK = rsaPublic.GetPublicExponent(); // public exponent e; 
	CryptoPP::Integer modul2 = rsaPublic.GetModulus(); // modul n; 
	cout << "Module n from Public key n=" << modul2 << endl << endl;
	cout << "Module n from Private key n=" << modul1 << endl << endl;
	cout << "The prinumber p=" << prime1 << endl;
	cout << "The prinumber q=" << prime2 << endl;
	cout << "Secret exponent d=" << SK << endl << endl;
	cout << "Public exponent e=" << PK << endl;
}

void SavePrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	Save(filename, queue);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_sink.html
	FileSink file(filename.c_str());

	bt.CopyTo(file);
	file.MessageEnd();
}

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string& filename, const PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;
	key.Save(queue);

	SaveBase64(filename, queue);
}

void SaveBase64(const string& filename, const BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_base64_encoder.html
	Base64Encoder encoder;

	bt.CopyTo(encoder);
	encoder.MessageEnd();

	Save(filename, encoder);
}

void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
	// http://www.cryptopp.com/docs/ref/class_byte_queue.html
	ByteQueue queue;

	Load(filename, queue);
	key.Load(queue);	
}

void Load(const string& filename, BufferedTransformation& bt)
{
	// http://www.cryptopp.com/docs/ref/class_file_source.html
	FileSource file(filename.c_str(), true /*pumpAll*/);

	file.TransferTo(bt);
	bt.MessageEnd();
}

void LoadBase64PrivateKey(const string& filename, PrivateKey& key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64PublicKey(const string& filename, PublicKey& key)
{
	throw runtime_error("Not implemented");
}

void LoadBase64(const string& filename, BufferedTransformation& bt)
{
	throw runtime_error("Not implemented");
}

