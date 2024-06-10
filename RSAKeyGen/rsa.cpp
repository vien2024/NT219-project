// RSA-OAEP.cpp

// C/C++ Standard Libraries
#include <assert.h>

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <exception>
using std::exception;

// Crypto++ Libraries
#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "cryptopp/cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/modarith.h"
using CryptoPP::ModularArithmetic;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;


// Save RSA keys (DER-Binary)
void Save(const string& filename, const BufferedTransformation& bt);
void SavePrivateKey(const string& filename, const PrivateKey& key);
void SavePublicKey(const string& filename, const PublicKey& key);

// Save RSA keys (DER-Base64)
void SaveBase64(const string& filename, const BufferedTransformation& bt);
void SaveBase64PrivateKey(const string& filename, const PrivateKey& key);
void SaveBase64PublicKey(const string& filename, const PublicKey& key);

// Load RSA keys (DER-Binary)
void Load(const string& filename, BufferedTransformation& bt);
void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);

// Load RSA keys (DER-Binary)
void LoadBase64(const string& filename, BufferedTransformation& bt);
void LoadBase64PrivateKey(const string& filename, PrivateKey& key);
void LoadBase64PublicKey(const string& filename, PublicKey& key);

// Generate and save RSA keys
void GenerateAndSaveRSAKeys(int keySize, const char* format, const char* privateKeyFile, const char* publicKeyFile) {
	// 
    string strFormat(format);
    string strPrivateKeyFile(privateKeyFile);
    string strPublicKeyFile(publicKeyFile);

    // generate keys
    AutoSeededRandomPool rnd;
    RSA::PrivateKey rsaPrivate;
	rsaPrivate.GenerateRandomWithKeySize(rnd, keySize);
    RSA::PublicKey rsaPublic(rsaPrivate);
    rsaPublic.SetPublicExponent(65537);

	// save keys
    if (strFormat=="DER") {
        SavePrivateKey(strPrivateKeyFile, rsaPrivate);
	    SavePublicKey(strPublicKeyFile, rsaPublic);
    }
    else if (strFormat=="Base64")
    {
        SaveBase64PrivateKey(strPrivateKeyFile, rsaPrivate);
		SaveBase64PublicKey(strPublicKeyFile, rsaPublic);
    }
    else
    {
        cerr << "Unsupported format. Please choose 'DER' or 'Base64' ";
    }

	Integer modul1=rsaPrivate.GetModulus(); // modul n
    Integer prime1 = rsaPrivate.GetPrime1(); // prime p
    Integer prime2 = rsaPrivate.GetPrime2();  // prime q

    /* Secret exponent d; public exponent e */
    Integer SK=rsaPrivate.GetPrivateExponent(); // secret exponent d; 
    Integer PK= rsaPublic.GetPublicExponent(); // public exponent e; 
    Integer modul2=rsaPublic.GetModulus(); // modul n

    cout << "Public modul (from secret key) =" << modul1 << endl;
    cout << "\nPublic modul (from public key) =" << modul2 << endl;
    cout << "\nSecret exponent d=" << SK << endl;
    cout << "\nPrime number p=" << std::hex << prime1<< std::dec << endl;
    cout << "\nPrime number q=" << prime2 << endl;
    cout << "\nPublic exponent e=" << PK << endl;

	RSA::PrivateKey r1, r2;
	r1.GenerateRandomWithKeySize(rnd, 3072);

	SavePrivateKey("rsa-roundtrip.key", r1);
	LoadPrivateKey("rsa-roundtrip.key", r2);

	r1.Validate(rnd, 3);
	r2.Validate(rnd, 3);

	if(r1.GetModulus() != r2.GetModulus() ||
		r1.GetPublicExponent() != r2.GetPublicExponent() ||
		r1.GetPrivateExponent() != r2.GetPrivateExponent())
	{
		throw runtime_error("key data did not round trip");
	}

    cout << "Successfully generated and saved RSA keys" << endl;
}

void RSAEncryption( const char* format, const char* publicKeyFile, const char* PlaintextFile, const char* CiphertFile ) {
    AutoSeededRandomPool rng;
    string strFormat(format);
    string strPublicKeyFile(publicKeyFile);
    // string strPlainTextFile(PlainTextFile);

    RSA::PublicKey publicKey;
    // load public key
    if (strFormat=="DER") {
        LoadPublicKey(strPublicKeyFile, publicKey);
    }
    else if (strFormat=="Base64")
    {
        LoadBase64PublicKey(strPublicKeyFile, publicKey);
    } else
    {
        cerr << "Unsupported format. Please choose 'DER' or 'Base54' ";
        exit(1);
    }
    

    // load plain text
    string plain, cipher;
    FileSource(PlaintextFile, true, new StringSink(plain),false);

    ////////////////////////////////////////////////
    // Run Encryption and save file
    // Encrypt with OAEF padding, SHA1
    RSAES_OAEP_SHA_Encryptor e( publicKey );

    // Run encrypt function and save to file
    StringSource( plain, true,
        new PK_EncryptorFilter( rng, e,
            new FileSink( CiphertFile, true )
        ) // PK_EncryptorFilter
        ); // StringSource

    cout << "Successfully encrypt plain text." << endl;
}

void RSADecryption( const char* format, const char* secretKeyFile, const char* PlaintextFile, const char* ciphertFile ) {
    string strFormat(format);
    string strSecretKeyFile(secretKeyFile);
    // string strPlainTextFile(PlainTextFile);

    RSA::PrivateKey PrivateKey;
    // load private key
    if (strFormat=="DER") {
        LoadPrivateKey(strSecretKeyFile, PrivateKey);
    }
    else if (strFormat=="Base64")
    {
        LoadBase64PrivateKey(strSecretKeyFile, PrivateKey);
    } else
    {
        cerr << "Unsupported format. Please choose 'DER' or 'Base54' ";
        exit(1);
    }

    AutoSeededRandomPool rng;

    RSAES_OAEP_SHA_Decryptor d( PrivateKey );
    // load cipher text
    string plain, cipher;
    FileSource(ciphertFile, true, new StringSink(cipher),false);

        StringSource( cipher, true,
        new PK_DecryptorFilter( rng, d,
            new FileSink( PlaintextFile, true )
        ) // PK_DecryptorFilter
        ); // StringSource
    
    cout << "Successfully decrypt cipher text." << endl;
}

int main(int argc, char* argv[])
{
    std::ios_base::sync_with_stdio(false);

    if (argc<2) {
        cerr << "Usage: \n"
            << argv[0] << " genkey <keysize> <format> <privatekeyFile> <publicKeyFile>" << endl
            << argv[0] << " encrypt <format> <publickeyFile> <plainTextFile> <cipherFile>" << endl
            << argv[0] << " decrypt <format> <privatekeyFile> <plainTextFile> <cipherFile>" << endl;
        exit(1);
    }

    string mode = argv[1];

    if (mode=="genkey" && argc == 6) {
        int keySize = std::stoi(argv[2]);
        GenerateAndSaveRSAKeys(keySize, argv[3], argv[4], argv[5]);
    }
    else if (mode=="encrypt" && argc==6) {
        RSAEncryption(argv[2], argv[3], argv[4], argv[5]);
    }
    else if (mode=="decrypt" && argc==6) {
        RSADecryption(argv[2], argv[3], argv[4], argv[5]);
    }
    else {
        cerr << "Invalid arguments. Please read the instructions.\n";
        exit(1);
    }

	return 0;
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