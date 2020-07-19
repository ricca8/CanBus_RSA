/* Details on RSA signing are here: https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying */

#include <vector>
#include "./include/crypto.h"

#define nullptr NULL

namespace cry{

    //Creates RSA object from private key
    RSA* createPrivateRSA(const std::string& key) {
        RSA *rsa = nullptr;
        const char* c_string = key.c_str();
        BIO * keybio = BIO_new_mem_buf((void*)c_string, -1);
        if (keybio==nullptr) {
            //return 0;
            return nullptr;
        }
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,nullptr, nullptr);
        if(rsa == nullptr)
            return nullptr;
        else
            return rsa;
    }

    //Creates RSA object from public key
    RSA* createPublicRSA(const std::string& key) {
        RSA *rsa = nullptr;

        BIO *keybio;
        const char* c_string = key.c_str();
        keybio = BIO_new_mem_buf((void*)c_string, -1);
        if (keybio==nullptr) {

            return nullptr;
        }
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,nullptr, nullptr);

        return rsa;
    }

    /* Create digest and signature:
     * 1- Creates signing context
     * 2- Initialize context with hash function (SHA-256)
     * 3- Add message
     * 4- Compute message length
     * 5- Compute signature
     * */
    bool RSASign( RSA* rsa, const unsigned char* Msg, size_t MsgLen, unsigned char** EncMsg, size_t* MsgLenEnc) {
        EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_new();
        EVP_PKEY* priKey  = EVP_PKEY_new();
        if(EVP_PKEY_assign((priKey), 6, (char *) (rsa)) <= 0)
            return false;
        if (EVP_DigestSignInit(m_RSASignCtx,nullptr, EVP_sha256(), nullptr, priKey) <= 0)
            return false;

        if (EVP_DigestUpdate(m_RSASignCtx, Msg, MsgLen) <= 0)
            return false;

        if (EVP_DigestSignFinal(m_RSASignCtx, nullptr, MsgLenEnc) <= 0)
            return false;

        *EncMsg = (unsigned char*)malloc(*MsgLenEnc);

        if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0)
            return false;

        EVP_MD_CTX_free(m_RSASignCtx);
        return true;
    }

    /*Works opposite to RSASign:
     * 1- Creates verification context
     * 2- Context initialized with hash function and public key
     * 3- Verify signature
     * */
    bool RSAVerifySignature( RSA* rsa, unsigned char* MsgHash, size_t MsgHashLen, const char* Msg, size_t MsgLen, bool* Authentic) {

        *Authentic = false;
        EVP_PKEY* pubKey  = EVP_PKEY_new();
        EVP_PKEY_assign((pubKey), 6, (char *) (rsa));
        EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_new();

        if (EVP_DigestVerifyInit(m_RSAVerifyCtx,nullptr, EVP_sha256(),nullptr,pubKey)<=0)
            return false;

        if (EVP_DigestUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0)
            return false;

        int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);

        if (AuthStatus==1) {
            *Authentic = true;
            EVP_MD_CTX_free(m_RSAVerifyCtx);
            return true;
        }
        else if(AuthStatus==0){
            *Authentic = false;
            EVP_MD_CTX_free(m_RSAVerifyCtx);
            return true;
        }
        else{
            *Authentic = false;
            EVP_MD_CTX_free(m_RSAVerifyCtx);
            return false;
        }
    }

    //Base64 encodes binary signature to make it readable
    std::string Base64Encode( unsigned char* buffer, size_t length) {

        static const std::string base64_chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";


        std::string base64_encode;
        std::string ret;
        int i = 0;
        int j = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];

        while (length--) {
            char_array_3[i++] = *(buffer++);
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for(i = 0; (i <4) ; i++)
                    ret += base64_chars[char_array_4[i]];
                i = 0;
            }
        }

        if (i){
            for(j = i; j < 3; j++)
                char_array_3[j] = '\0';

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (j = 0; (j < i + 1); j++)
                ret += base64_chars[char_array_4[j]];

            while((i++ < 3))
                ret += '=';

        }
        return ret;
    }

    //Decoding, from readable to binary
    std::string Base64Decode( std::string b64message) {

        std::string out;
        std::vector<int> T(256,-1);
        for (int i=0; i<64; i++)
            T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

        int val=0, valb=-8;
        for (char c : b64message) {
            if (T[c] == -1)
                break;
            val = (val<<6) + T[c];
            valb += 6;
            if (valb>=0) {
                out.push_back(char((val>>valb)&0xFF));
                valb-=8;
            }
        }
        return out;
    }

    std::string signMessage(const std::string& privateKey, const std::string& plainText) {

        RSA* privateRSA;
        privateRSA = createPrivateRSA(privateKey);

        unsigned char *encMessage;
        size_t encMessageLength;

        RSASign(privateRSA, (unsigned char *) plainText.c_str(), plainText.length(), &encMessage,&encMessageLength);
        std::string text = Base64Encode(encMessage, encMessageLength);

        return text;
    }

    bool verifySignature(const std::string& publicKey, const std::string& plainText, std::string signatureBase64) {
        RSA* publicRSA;
        publicRSA = createPublicRSA(publicKey);

        bool authentic;

        std::string text = Base64Decode(signatureBase64);

        bool result = RSAVerifySignature(publicRSA, (unsigned char *)text.c_str(), text.length(), plainText.c_str(), plainText.length(), &authentic);

        return result & authentic;
    }

}




