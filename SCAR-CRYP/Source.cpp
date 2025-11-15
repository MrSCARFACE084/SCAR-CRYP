#include <windows.h>
#include <shobjidl.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <ctime>
#include <iomanip>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/rand.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "crypt32.lib")

namespace fs = std::filesystem;

// === CONFIGURATION ===
#define AES_KEYLENGTH 256
const std::string KEY_FILE = "aes.key";
const std::string HEX_KEY_FILE = "aes.key.hex";
const std::string LOG_FILE = "log.txt";
const std::vector<std::string> EXT_SKIP = { ".exe", ".dll", ".sys", ".bat", ".cmd" };

// === LOG ===
void logEvent(const std::string& message) {
    std::ofstream log(LOG_FILE, std::ios::app);
    time_t now = time(nullptr);
    std::tm timeinfo;
    localtime_s(&timeinfo, &now);
    log << "[" << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S") << "] " << message << std::endl;
}

// === DIALOG FOLDER SELECT ===
std::string selectFolder() {
    std::string path;
    IFileDialog* pFileDialog = nullptr;
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr)) {
        hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pFileDialog));
        if (SUCCEEDED(hr)) {
            DWORD dwOptions;
            pFileDialog->GetOptions(&dwOptions);
            pFileDialog->SetOptions(dwOptions | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
            if (SUCCEEDED(pFileDialog->Show(NULL))) {
                IShellItem* pItem = nullptr;
                if (SUCCEEDED(pFileDialog->GetResult(&pItem))) {
                    PWSTR pszFilePath = nullptr;
                    if (SUCCEEDED(pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath))) {
                        char charPath[MAX_PATH];
                        size_t converted;
                        wcstombs_s(&converted, charPath, MAX_PATH, pszFilePath, _TRUNCATE);
                        path = charPath;
                        CoTaskMemFree(pszFilePath);
                    }
                    pItem->Release();
                }
            }
            pFileDialog->Release();
        }
        CoUninitialize();
    }
    return path;
}

// === INTRO MESSAGE ===
int showIntroMessage() {
    std::string message = R"(Programme de chiffrement AES-256

Développé par : Mr SCARFACE

Fonctionnement :
- Ce programme chiffre ou déchiffre tous les fichiers d’un dossier (sauf ceux exclus).
- Une clé AES-256 est générée et sauvegardée dans le même répertoire que l’exécutable.
- Les fichiers originaux sont remplacés par leurs versions chiffrées/déchiffrées.

Consignes de sécurité :
- ? Ne perdez pas la clé de chiffrement générée.
- ? N’utilisez pas ce programme sur des fichiers système ou critiques.
- ? Utilisation à vos propres risques.

Voulez-vous continuer ?")";

    int result = MessageBoxA(
        NULL,
        message.c_str(),
        "Bienvenue dans le Chiffreur AES - Mr SCARFACE",
        MB_ICONINFORMATION | MB_YESNO | MB_DEFBUTTON2
    );
    return result;
}

// === GÉNÉRATION DE LA CLÉ + HEX ===
bool generateAndSaveKey(unsigned char* key, unsigned char* iv) {
    if (!RAND_bytes(key, 32) || !RAND_bytes(iv, 16)) {
        logEvent("Erreur génération de clé.");
        return false;
    }

    std::ofstream binOut(KEY_FILE, std::ios::binary);
    binOut.write((char*)key, 32);
    binOut.write((char*)iv, 16);
    binOut.close();

    std::ofstream hexOut(HEX_KEY_FILE);
    for (int i = 0; i < 32; ++i)
        hexOut << std::hex << std::setw(2) << std::setfill('0') << (int)key[i];
    hexOut << "\n";
    for (int i = 0; i < 16; ++i)
        hexOut << std::hex << std::setw(2) << std::setfill('0') << (int)iv[i];
    hexOut.close();

    logEvent("Clé AES-256 générée.");
    return true;
}

// === LECTURE CLÉ ===
bool loadKey(unsigned char* key, unsigned char* iv) {
    std::ifstream in(KEY_FILE, std::ios::binary);
    if (!in.read((char*)key, 32) || !in.read((char*)iv, 16)) {
        logEvent("Erreur lecture de la clé.");
        return false;
    }
    return true;
}

// === TRAITEMENT FICHIER AES ===
bool processFile(const std::string& inFile, const unsigned char* key, const unsigned char* iv, bool encrypt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::ifstream fin(inFile, std::ios::binary);
    std::string tmpOut = inFile + (encrypt ? ".enc" : ".dec");
    std::ofstream fout(tmpOut, std::ios::binary);

    if (!ctx || !fin || !fout) return false;

    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, encrypt ? 1 : 0);

    std::vector<unsigned char> inBuf(4096), outBuf(4096 + EVP_MAX_BLOCK_LENGTH);
    int outLen;
    while (fin.read((char*)inBuf.data(), inBuf.size()) || fin.gcount()) {
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), fin.gcount());
        fout.write((char*)outBuf.data(), outLen);
    }

    EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen);
    fout.write((char*)outBuf.data(), outLen);
    EVP_CIPHER_CTX_free(ctx);

    fin.close(); fout.close();
    std::remove(inFile.c_str());
    std::rename(tmpOut.c_str(), inFile.c_str());
    return true;
}

// === PARCOURS DU DOSSIER ===
void processDirectory(const std::string& dir, const unsigned char* key, const unsigned char* iv, bool encrypt) {
    for (const auto& entry : fs::recursive_directory_iterator(dir)) {
        if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
            if (std::find(EXT_SKIP.begin(), EXT_SKIP.end(), ext) != EXT_SKIP.end()) continue;

            std::string filepath = entry.path().string();
            if (processFile(filepath, key, iv, encrypt))
                logEvent((encrypt ? "Chiffré : " : "Déchiffré : ") + filepath);
            else
                logEvent("Erreur : " + filepath);
        }
    }
}

// === MESSAGE DE FIN ===
void showFinalMessage(bool encrypt) {
    MessageBoxA(NULL,
        encrypt ? "Vos fichiers ont été chiffrés avec succès." :
        "Les fichiers ont été déchiffrés avec succès.",
        encrypt ? "Chiffrement terminé" : "Déchiffrement terminé",
        MB_OK | MB_ICONINFORMATION);
}

// === MAIN ===
int main() {
    if (showIntroMessage() != IDYES) {
        MessageBoxA(NULL, "Programme annulé par l'utilisateur.", "Annulation", MB_OK | MB_ICONEXCLAMATION);
        return 0;
    }

    std::string folder = selectFolder();
    if (folder.empty()) {
        MessageBoxA(NULL, "Aucun dossier sélectionné.", "Erreur", MB_OK | MB_ICONERROR);
        return 1;
    }

    int mode = MessageBoxA(NULL, "Voulez-vous chiffrer les fichiers ? (Non = déchiffrer)", "Mode", MB_YESNO | MB_ICONQUESTION);
    bool encrypt = (mode == IDYES);

    unsigned char key[32], iv[16];
    if (encrypt) {
        if (!generateAndSaveKey(key, iv)) {
            MessageBoxA(NULL, "Erreur lors de la génération de la clé.", "Erreur", MB_OK | MB_ICONERROR);
            return 1;
        }
    }
    else {
        if (!loadKey(key, iv)) {
            MessageBoxA(NULL, "Erreur de chargement de clé.", "Erreur", MB_OK | MB_ICONERROR);
            return 1;
        }
    }

    processDirectory(folder, key, iv, encrypt);
    showFinalMessage(encrypt);
    return 0;
}
