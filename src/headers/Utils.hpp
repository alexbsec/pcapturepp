#ifndef PCAPTUREPP_UTILS_HPP
#define PCAPTUREPP_UTILS_HPP

#include "Includes.hpp"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstring>

namespace pcapturepp {
    vector<string> SplitByDelimiter(const string& str, char delimeter = '.');
namespace utils {

    path GetExecutablePath();

    string PrintMACArray(const array<UINT8, MAC_ADDRESS_SIZE>& arr);

    namespace cacert {
        /* Wrapper function to communicate */
        string GenerateCACertificate(const string& cacert_path, const string& cakey_path, UINT validity_in_days);

        /* Generates 2048-bit RSA key */
        EVP_PKEY *GenerateCAKey();

        /* Generates a self-signed x509 certificate. */
        X509 *GenerateX509(EVP_PKEY *pkey, UINT validity_in_days);

        /* Writes to disk */
        string WriteCertToDisk(EVP_PKEY *pkey, X509 *x509, const string& cacert_path, const string& cakey_path);
    }
}
}

#endif // PCAPTUREPP_UTILS_HPP