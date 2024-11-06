#include "Utils.hpp"

namespace pcapturepp {

    vector<string> SplitByDelimiter(const string& str, char delimiter) {
        vector<string> result;

        // Check if the string contains a dot
        if (str.find(delimiter) == string::npos) {
            // No dot found; return the entire string as a single element
            result.push_back(str);
            return result;
        }

        // Otherwise, split by dots
        std::size_t start = 0;
        std::size_t end = str.find(delimiter);

        while (end != std::string::npos) {
            result.push_back(str.substr(start, end - start));
            start = end + 1;
            end = str.find(delimiter, start);
        }

        // Add the last part after the final dot
        result.push_back(str.substr(start));

        return result;
    }

namespace utils {

    
    path GetExecutablePath() {
        char result[PATH_MAX];
        ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);
        return (count != -1) ? std::filesystem::path(result).parent_path() : "";
    }

    string PrintMACArray(const array<UINT8, MAC_ADDRESS_SIZE>& arr) {
        std::ostringstream mac_stream;
        for (std::size_t i = 0; i < arr.size(); i++) {
            mac_stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(arr[i]);

            // Add colon between bytes, except last byte
            if (i != arr.size() - 1) {
                mac_stream << ":";
            }
        }

        return mac_stream.str();
    }

    namespace cacert {

        string GenerateCACertificate(const string& cacert_path, const string& cakey_path, UINT validity_in_days) {
            string message;

            // Create paths if don't exist
            path cert_dir = path(cacert_path);
            path key_dir = path(cakey_path);
            try {
                if (!std::filesystem::exists(cert_dir)) {
                    std::filesystem::create_directories(cert_dir);
                }

                if (!std::filesystem::exists(key_dir)) {
                    std::filesystem::create_directories(key_dir);
                }
            } catch (const std::filesystem::filesystem_error& e) {
                message = "Error: Unable to create directories for paths. " + string(e.what());
                return message;
            }

            // Generate the private key
            EVP_PKEY* pkey = nullptr;
            try {
                pkey = GenerateCAKey();
            } catch (const std::exception& e) {
                message = string(C_RED) + "Error: " + string(C_NONE) + e.what();
                return message;
            }

            // Generate the X509 certificate
            X509* x509 = nullptr;
            try {
                x509 = GenerateX509(pkey, validity_in_days);
            } catch (const std::exception& e) {
                EVP_PKEY_free(pkey);
                message = string(C_RED) + "Error: " + string(C_NONE) + e.what();
                return message;
            }

            // Write the key and certificate to disk
            message = WriteCertToDisk(pkey, x509, cacert_path, cakey_path);

            // Free resources
            EVP_PKEY_free(pkey);
            X509_free(x509);

            // If message is empty, it means writing to disk was successful
            if (message.empty()) {
                message = string(C_GREEN) + "Success: " + string(C_NONE) + "CA certificate and key generated successfully.";
            }

            return message;
        }


        EVP_PKEY* GenerateCAKey() {
            // Allocate memory for the EVP_PKEY structure
            EVP_PKEY* pkey = EVP_PKEY_new();
            if (!pkey) {
                throw std::runtime_error("Failed to allocate memory for EVP_PKEY structure");
            }

            // Allocate and set up the RSA key
            RSA* rsa = RSA_new();
            if (!rsa) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to allocate memory for RSA structure");
            }

            BIGNUM* bn = BN_new();
            if (!bn) {
                EVP_PKEY_free(pkey);
                RSA_free(rsa);
                throw std::runtime_error("Failed to allocate memory for BIGNUM structure");
            }

            if (!BN_set_word(bn, RSA_F4)) {
                EVP_PKEY_free(pkey);
                RSA_free(rsa);
                BN_free(bn);
                throw std::runtime_error("Failed to set BIGNUM exponent for RSA key generation");
            }

            // Generate the RSA key and assign it to pkey
            if (!RSA_generate_key_ex(rsa, 2048, bn, nullptr)) {
                EVP_PKEY_free(pkey);
                RSA_free(rsa);
                BN_free(bn);
                throw std::runtime_error("Failed to generate 2048-bit RSA key");
            }

            // Assign the RSA key to the EVP_PKEY structure
            if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
                EVP_PKEY_free(pkey);
                RSA_free(rsa);
                BN_free(bn);
                throw std::runtime_error("Failed to assign RSA key to EVP_PKEY structure");
            }

            // Free the BIGNUM structure as it’s no longer needed
            BN_free(bn);

            // Return the generated key
            return pkey;
        }

        X509 *GenerateX509(EVP_PKEY *pkey, UINT validity_in_days) {
            X509 *x509 = X509_new();
            if (!x509) {
                throw std::runtime_error("Failed to create X509 structure");
            }

            ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
            X509_gmtime_adj(X509_get_notBefore(x509), 0);
            X509_gmtime_adj(X509_get_notAfter(x509), static_cast<long>(60 * 60 * 24 * validity_in_days));
            X509_set_pubkey(x509, pkey);

            X509_NAME *name = X509_get_subject_name(x509);
            X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (UCHAR*)"US", -1, -1, 0);
            X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (UCHAR*)"Secure Certificate Authority", -1, -1, 0);
            X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (UCHAR*)"Trusted Root CA", -1, -1, 0);

            X509_set_issuer_name(x509, name);

            // Add basic constraints extension (CA:TRUE)
            X509_EXTENSION *ext;
            ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "CA:TRUE");
            X509_add_ext(x509, ext, -1);

            // Add key usage extension (keyCertSign, cRLSign)
            ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage, "keyCertSign, cRLSign");
            X509_add_ext(x509, ext, -1);
            X509_EXTENSION_free(ext);

            // Add subjectKeyIdentifier extension
            ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_key_identifier, "hash");
            X509_add_ext(x509, ext, -1);
            X509_EXTENSION_free(ext);

            // Self-sign
            if (!X509_sign(x509, pkey, EVP_sha256())) {
                X509_free(x509);
                throw std::runtime_error("Error signing certificate");
            }

            return x509;
        }

        string WriteCertToDisk(EVP_PKEY *pkey, X509 *x509, const string& cacert_path, const string& cakey_path) {\
            string message = "";
            path key_path = path(cakey_path) / "key.pem";
            path cert_path = path(cacert_path) / "cert.pem";
            FILE *pkey_file = fopen(key_path.c_str(), "wb");
            if (!pkey_file) {
                message = string(C_RED) + "Error: " + string(C_NONE) + "Unable to open \"" + key_path.string() + "\" for writing.";
                return message;
            }
            bool ret = PEM_write_PrivateKey(pkey_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
            fclose(pkey_file);
            if (!ret) {
                message = string(C_RED) + "Error: " + string(C_NONE) + "Unable to write private key to disk.";
                return message;
            }

            FILE* x509_file = fopen(cert_path.c_str(), "wb");
            if (!x509_file) {
                message = string(C_RED) + "Error: " + string(C_NONE) + "Unable to open \"" + cert_path.string() + "\" for writing.";
                return message;
            }
            ret = PEM_write_X509(x509_file, x509);
            fclose(x509_file);
            if (!ret) {
                message = string(C_RED) + "Error: " + string(C_NONE) + "Unable to write certificate to disk.";
                return message;
            }

            return message;
        }

    }
}
}