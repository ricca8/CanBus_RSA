#ifndef CRYPTO_H
#define CRYPTO_H

#include <iostream>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <assert.h>
#include <cstring>
#include <fstream>
#include <streambuf>


namespace cry{

    RSA* createPrivateRSA(const std::string& key);

    RSA* createPublicRSA(const std::string& key);

    bool RSASign( RSA* rsa, const unsigned char* Msg, size_t MsgLen, unsigned char** EncMsg, size_t* MsgLenEnc);

    bool RSAVerifySignature( RSA* rsa, unsigned char* MsgHash, size_t MsgHashLen, const char* Msg, size_t MsgLen, bool* Authentic);

    std::string Base64Encode( unsigned char* buffer, size_t length);

    std::string Base64Decode( std::string b64message);

    std::string signMessage(const std::string& privateKey, const std::string& plainText);

    bool verifySignature(const std::string& publicKey, const std::string& plainText, std::string signatureBase64);

}
#endif