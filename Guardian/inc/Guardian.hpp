#pragma once

#include <cstdio>
#include <Windows.h>
#include <winternl.h>
#include <tchar.h>
#include <string>
#include <codecvt>


//#ifndef _WIN32
//#error Currently Guardian can only be built for the Windows platform
//#endif

//SMBIOS Table Type numbers
#define SMB_TABLE_SYSTEM            1
#define SMB_TABLE_BASEBOARD         2
#define SMB_TABLE_CHASSIS           3
#define SMB_TABLE_PROCESSOR         4

namespace LicenseKeyGen {

    typedef struct _RawSmbiosData
    {
        BYTE    Used20CallingMethod;
        BYTE    SMBIOSMajorVersion;
        BYTE    SMBIOSMinorVersion;
        BYTE    DmiRevision;
        DWORD   Length;
        BYTE    SMBIOSTableData[1];
    }*PRAW_SMBIOS_DATA;

    typedef struct _SmbiosStructHeader
    {
        BYTE Type;
        BYTE Length;
        WORD Handle;
    }*PSMBIOS_STRUCT_HEADER;

    enum class HashingAlgorithms {
        MD5,
        SHA3_512
    };

    class Guardian {
    public:
        Guardian();   // Получает данные из SMBIOS и записывает в m_data
        ~Guardian() = default;

        // Для записи в бинарник
        uint64_t CpuIDHash();
        uint64_t MotherBoardSerialHash();
        uint64_t SystemUUIDHash();
        uint64_t ChassisSerialHash();

        // Для получения параметров из SMBIOS
        std::string SystemUUID();
        std::string ChassisSerial();
        std::string MotherBoardSerial();
        std::string CpuID();

        std::string EncryptionGet(HashingAlgorithms hashingAlgorithm = HashingAlgorithms::SHA3_512);
        // Вычисляет хеш по заданному алгоритму
        std::string Encrypt(std::string& input, HashingAlgorithms hashingAlgorithm = HashingAlgorithms::SHA3_512);
        // Конкатенирует строковые значение хешей
        std::string HashesConcatenation(uint64_t cpuIdHash, uint64_t motherHash, uint64_t chassisHash, uint64_t systemUUIDHash);

    private:
        std::string wstringToString(const std::wstring& wstr);
        std::string BiosValue(PRAW_SMBIOS_DATA smbios,DWORD type,DWORD offset, DWORD size);
        std::string BiosString(PRAW_SMBIOS_DATA smbios,DWORD type,DWORD offset);
        PRAW_SMBIOS_DATA GetSmbiosData();
        PSMBIOS_STRUCT_HEADER GetNextStructure(PRAW_SMBIOS_DATA smbios,PSMBIOS_STRUCT_HEADER previous);
        PSMBIOS_STRUCT_HEADER GetNextStructureOfType(PRAW_SMBIOS_DATA smbios,PSMBIOS_STRUCT_HEADER previous, DWORD type);
        void GetSmbiosString(PSMBIOS_STRUCT_HEADER table, BYTE index, LPWSTR output, int cchOutput);

        PRAW_SMBIOS_DATA m_data;
    };

    void BinCreate();
    void HashJsonCreate();
}