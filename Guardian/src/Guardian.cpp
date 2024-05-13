#include "../inc/Guardian.hpp"

#include <iostream>
#include <fstream>
#include <map>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <cryptopp/sha3.h>
#include <cryptopp/hex.h>

namespace LicenseKeyGen {

    Guardian::Guardian() {
        m_data = GetSmbiosData();

        if (m_data == nullptr) {
            printf("Can't get SMBIOS data!");
        }
    }

    uint64_t Guardian::CpuIDHash() {
        return std::hash<std::string>{}(CpuID());
    }

    uint64_t Guardian::MotherBoardSerialHash() {
        return std::hash<std::string>{}(MotherBoardSerial());
    }

    uint64_t Guardian::SystemUUIDHash() {
        return std::hash<std::string>{}(SystemUUID());
    }

    uint64_t Guardian::ChassisSerialHash() {
        return std::hash<std::string>{}(ChassisSerial());
    }

    std::string Guardian::SystemUUID() {
        return BiosValue(m_data, SMB_TABLE_SYSTEM, 8, 16);
    }

    std::string Guardian::ChassisSerial() {
        return BiosString(m_data, SMB_TABLE_CHASSIS, 7);
    }

    std::string Guardian::MotherBoardSerial() {
        return BiosString(m_data, SMB_TABLE_BASEBOARD, 7);
    }

    std::string Guardian::CpuID() {
        return BiosValue(m_data, SMB_TABLE_PROCESSOR, 8, 8);
    }

    std::string Guardian::wstringToString(const std::wstring &wstr) {
        std::string result;
        for (int i = 0; i < wstr.length(); i++)
            result += static_cast<char>(wstr[i]);

        return result;
    }

    std::string Guardian::BiosValue(PRAW_SMBIOS_DATA smbios, DWORD type, DWORD offset, DWORD size) {
        PSMBIOS_STRUCT_HEADER head = NULL;
        PBYTE cursor = NULL;

        head = GetNextStructureOfType(smbios, head, type);
        if (NULL == head) {
            printf("PrintBiosValue Error!\n");
            return "";
        }

        cursor = ((PBYTE) head + offset);

        //value
        char tmp[10];
        std::string s = "";
        for (std::size_t i = 0; i < size; i++) {
            sprintf(tmp, "%02x", (unsigned int) *cursor);
            s += std::string(tmp);
            cursor++;
        }
        return s;
    }

    std::string Guardian::BiosString(PRAW_SMBIOS_DATA smbios, DWORD type, DWORD offset) {
        PSMBIOS_STRUCT_HEADER head;
        head = NULL;
        PBYTE cursor = NULL;
        WCHAR buf[1024];

        head = GetNextStructureOfType(smbios, head, type);
        if (NULL == head) {
            printf("PrintString Error!\n");
            return "";
        }
        cursor = ((PBYTE) head + offset);
        // BYTE val=*cursor;

        GetSmbiosString((head), *cursor, buf, 1024);
        //  value
        std::wstring s(buf);
        return wstringToString(s);
    }

    PRAW_SMBIOS_DATA Guardian::GetSmbiosData() {
        DWORD bufferSize = 0;

        PRAW_SMBIOS_DATA smbios = NULL;

        /**
         * Get required buffer size
         */
        bufferSize = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
        if (bufferSize) {
            smbios = (PRAW_SMBIOS_DATA) LocalAlloc(LPTR, bufferSize);
            bufferSize = GetSystemFirmwareTable('RSMB', 0, (PVOID) smbios, bufferSize);
        }

        return smbios;
    }

    PSMBIOS_STRUCT_HEADER
    Guardian::GetNextStructure(PRAW_SMBIOS_DATA smbios, PSMBIOS_STRUCT_HEADER previous) {
        /**
             * PSMBIOS_STRUCT_HEADER next = NULL;
             */
        PBYTE c = NULL;

        /**
         * Return NULL is no data found
         */
        if (NULL == smbios)
            return NULL;

        /**
         * Return first table if previous was NULL
         */
        if (NULL == previous)
            return (PSMBIOS_STRUCT_HEADER) (&smbios->SMBIOSTableData[0]);

        /**
         * Move to the end of the formatted structure
         */
        c = ((PBYTE) previous) + previous->Length;

        /**
         * Search for the end of the unformatted structure (\0\0)
         */
        while (true) {
            if ('\0' == *c && '\0' == *(c + 1)) {
                /**
                 * Make sure next table is not beyond end of SMBIOS data
                 * (Thankyou Microsoft for ommitting the structure count
                 * in GetSystemFirmwareTable)
                 */
                if ((c + 2) < ((PBYTE) smbios->SMBIOSTableData + smbios->Length))
                    return (PSMBIOS_STRUCT_HEADER) (c + 2);
                else
                    return NULL; // We reached the end
            }

            c++;
        }

        return NULL;
    }

    PSMBIOS_STRUCT_HEADER
    Guardian::GetNextStructureOfType(PRAW_SMBIOS_DATA smbios, PSMBIOS_STRUCT_HEADER previous, DWORD type) {
        PSMBIOS_STRUCT_HEADER next = previous;
        while (NULL != (next = GetNextStructure(smbios, next))) {
            if (type == next->Type)
                return next;
        }

        return NULL;
    }

    void Guardian::GetSmbiosString(PSMBIOS_STRUCT_HEADER table, BYTE index, LPWSTR output, int cchOutput) {
        DWORD i = 0;
        DWORD len = 0;
        wcscpy(output, L"");

        if (0 == index) return;

        char *c = NULL;

        for (i = 1, c = (char *) table + table->Length; '\0' != *c; c += strlen(c) + 1, i++) {
            if (i == index) {
                len = MultiByteToWideChar(CP_UTF8, 0, c, -1, output, cchOutput);
                break;
            }
        }
    }

    std::string Guardian::EncryptionGet() {
        std::string CompInfo = HashesConcatenation(CpuIDHash(), MotherBoardSerialHash(),
                                                   ChassisSerialHash(), SystemUUIDHash());
        return Encrypt(CompInfo);
    }

    std::string Guardian::Encrypt(std::string &input) {
        CryptoPP::SHA3_512 sha3_512;
        std::string output;

        CryptoPP::StringSource SHA3(input, true, new CryptoPP::HashFilter(sha3_512, new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(output))));
        return output;
    }

    std::string Guardian::HashesConcatenation(uint64_t cpuIdHash, uint64_t motherHash, uint64_t chassisHash,
                                              uint64_t systemUUIDHash) {
        std::string result = std::to_string(cpuIdHash) + std::to_string(motherHash) + std::to_string(chassisHash) +
                             std::to_string(systemUUIDHash);
        return result;
    }

    void BinCreate() {
        std::ofstream out("code.bin", std::ios::binary);

        Guardian CI;
        uint64_t CpuIdHash = CI.CpuIDHash();
        uint64_t MotherBoardSerialHash = CI.MotherBoardSerialHash();
        uint64_t ChassisSerialHash = CI.ChassisSerialHash();
        uint64_t SystemUUIDHash = CI.SystemUUIDHash();
        out.write(reinterpret_cast<const char *>(&CpuIdHash), 8);
        out.write(reinterpret_cast<const char *>(&MotherBoardSerialHash), 8);
        out.write(reinterpret_cast<const char *>(&ChassisSerialHash), 8);
        out.write(reinterpret_cast<const char *>(&SystemUUIDHash), 8);
    }

    void HashJsonCreate() {
        using json = nlohmann::json;

#pragma pack(1)
        struct Data {
            uint64_t cpuIdHash;
            uint64_t motherHash;
            uint64_t chassisHash;
            uint64_t systemUUIDHash;
        };
#pragma pack()

        std::string path = ".";
        std::ofstream out("hash.json");
        int i = 1;
        json j = json::object();
        out << "[" << std::endl;
        /**
         * Ищет все .bin файлы в той же директории,
         * для каждого генерирует megahash и записывает в json название файла и megahash
         */
        for (const auto &entry: std::filesystem::directory_iterator(path)) {
            if (entry.path().extension() == ".bin") {
                std::filesystem::path filename = entry.path().filename();
                std::ifstream in(filename, std::ios::binary);
                if (!in.is_open()) {
                    std::cerr << filename << " File not found" << std::endl;
                }

                char buf[32];
                in.read(buf, 32);


                Data *data = reinterpret_cast<Data *>(buf);

                Guardian CI;
                std::string CompInfo = CI.HashesConcatenation(data->cpuIdHash, data->motherHash,
                                                              data->chassisHash,
                                                              data->systemUUIDHash);

                j[filename.string()] = CI.Encrypt(CompInfo);

                i++;
            }
        }
        out << std::setw(4) << j << std::endl;
        out << "]" << std::endl;
    }

}