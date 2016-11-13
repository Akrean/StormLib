/*****************************************************************************/
/* SFileCreateArchive.cpp                 Copyright (c) Ladislav Zezula 2003 */
/*---------------------------------------------------------------------------*/
/* MPQ Editing functions                                                     */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 24.03.03  1.00  Lad  Splitted from SFileOpenArchive.cpp                   */
/* 08.06.10  1.00  Lad  Renamed to SFileCreateArchive.cpp                    */
/*****************************************************************************/

#define __STORMLIB_SELF__
#include "StormLib.h"
#include "StormCommon.h"

//-----------------------------------------------------------------------------
// Local variables

static const DWORD MpqHeaderSizes[] =
{
	MPQ_HEADER_SIZE_V1,
	MPQ_HEADER_SIZE_V2,
	MPQ_HEADER_SIZE_V3,
	MPQ_HEADER_SIZE_V4
};

//-----------------------------------------------------------------------------
// Local functions

static USHORT GetSectorSizeShift(DWORD dwSectorSize)
{
	USHORT wSectorSizeShift = 0;

	while (dwSectorSize > 0x200)
	{
		dwSectorSize >>= 1;
		wSectorSizeShift++;
	}

	return wSectorSizeShift;
}

static int WriteNakedMPQHeader(TMPQArchive * ha)
{
	TMPQHeader * pHeader = ha->pHeader;
	TMPQHeader Header;
	DWORD dwBytesToWrite = pHeader->dwHeaderSize;
	int nError = ERROR_SUCCESS;

	// Prepare the naked MPQ header
	memset(&Header, 0, sizeof(TMPQHeader));
	Header.dwID = pHeader->dwID;
	Header.dwHeaderSize = pHeader->dwHeaderSize;
	Header.dwArchiveSize = pHeader->dwHeaderSize;
	Header.wFormatVersion = pHeader->wFormatVersion;
	Header.wSectorSize = pHeader->wSectorSize;

	// Write it to the file
	BSWAP_TMPQHEADER(&Header, MPQ_FORMAT_VERSION_1);
	BSWAP_TMPQHEADER(&Header, MPQ_FORMAT_VERSION_2);
	BSWAP_TMPQHEADER(&Header, MPQ_FORMAT_VERSION_3);
	BSWAP_TMPQHEADER(&Header, MPQ_FORMAT_VERSION_4);
	if (!FileStream_Write(ha->pStream, &ha->MpqPos, &Header, dwBytesToWrite))
		nError = GetLastError();

	return nError;
}

//-----------------------------------------------------------------------------
// Creates a new MPQ archive.

bool WINAPI SFileCreateArchive(TStreamProviderFactory* pFactory, const TCHAR * szMpqName, DWORD dwCreateFlags, DWORD dwMaxFileCount, HANDLE * phMpq)
{
	SFILE_CREATE_MPQ CreateInfo;

	// Fill the create structure
	memset(&CreateInfo, 0, sizeof(SFILE_CREATE_MPQ));
	CreateInfo.cbSize = sizeof(SFILE_CREATE_MPQ);
	CreateInfo.dwMpqVersion = (dwCreateFlags & MPQ_CREATE_ARCHIVE_VMASK) >> FLAGS_TO_FORMAT_SHIFT;
	CreateInfo.dwStreamFlags = STREAM_PROVIDER_FLAT | (pFactory ? BASE_PROVIDER_STREAM : BASE_PROVIDER_FILE);
	CreateInfo.dwFileFlags1 = (dwCreateFlags & MPQ_CREATE_LISTFILE) ? MPQ_FILE_EXISTS : 0;
	CreateInfo.dwFileFlags2 = (dwCreateFlags & MPQ_CREATE_ATTRIBUTES) ? MPQ_FILE_EXISTS : 0;
	CreateInfo.dwFileFlags3 = (dwCreateFlags & MPQ_CREATE_SIGNATURE) ? MPQ_FILE_EXISTS : 0;
	CreateInfo.dwAttrFlags = (dwCreateFlags & MPQ_CREATE_ATTRIBUTES) ? (MPQ_ATTRIBUTE_CRC32 | MPQ_ATTRIBUTE_FILETIME | MPQ_ATTRIBUTE_MD5) : 0;
	CreateInfo.dwSectorSize = (CreateInfo.dwMpqVersion >= MPQ_FORMAT_VERSION_3) ? 0x4000 : 0x1000;
	CreateInfo.dwRawChunkSize = (CreateInfo.dwMpqVersion >= MPQ_FORMAT_VERSION_4) ? 0x4000 : 0;
	CreateInfo.dwMaxFileCount = dwMaxFileCount;

	// Set the proper attribute parts
	if ((CreateInfo.dwMpqVersion >= MPQ_FORMAT_VERSION_3) && (dwCreateFlags & MPQ_CREATE_ATTRIBUTES))
		CreateInfo.dwAttrFlags |= MPQ_ATTRIBUTE_PATCH_BIT;

	// Backward compatibility: SFileCreateArchive always used to add (listfile)
	// We would break loads of applications if we change that
	CreateInfo.dwFileFlags1 = MPQ_FILE_EXISTS;

	// Let the main function create the archive
	return SFileCreateArchive2(pFactory, szMpqName, &CreateInfo, phMpq);
}

bool WINAPI SFileCreateArchive2(TStreamProviderFactory* pFactory, const TCHAR * szMpqName, PSFILE_CREATE_MPQ pCreateInfo, HANDLE * phMpq)
{
	TFileStream * pStream = NULL;           // File stream
	TMPQArchive * ha = NULL;                // MPQ archive handle
	TMPQHeader * pHeader;
	ULONGLONG MpqPos = 0;                   // Position of MPQ header in the file
	HANDLE hMpq = NULL;
	DWORD dwBlockTableSize = 0;             // Initial block table size
	DWORD dwHashTableSize = 0;
	DWORD dwReservedFiles = 0;              // Number of reserved file entries
	DWORD dwMpqFlags = 0;
	int nError = ERROR_SUCCESS;

	if ((pCreateInfo->dwStreamFlags & BASE_PROVIDER_MASK) == BASE_PROVIDER_FILE && pFactory != NULL) pCreateInfo->dwStreamFlags |= BASE_PROVIDER_STREAM;

	// Check the parameters, if they are valid
	if (szMpqName == NULL || *szMpqName == 0 || pCreateInfo == NULL || phMpq == NULL)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}

	// Verify if all variables in SFILE_CREATE_MPQ are correct
	if ((pCreateInfo->cbSize == 0 || pCreateInfo->cbSize > sizeof(SFILE_CREATE_MPQ)) ||
		(pCreateInfo->dwMpqVersion > MPQ_FORMAT_VERSION_4) ||
		(pCreateInfo->pvUserData != NULL || pCreateInfo->cbUserData != 0) ||
		(pCreateInfo->dwAttrFlags & ~MPQ_ATTRIBUTE_ALL) ||
		(pCreateInfo->dwSectorSize & (pCreateInfo->dwSectorSize - 1)) ||
		(pCreateInfo->dwRawChunkSize & (pCreateInfo->dwRawChunkSize - 1)))
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}

	// One time initialization of MPQ cryptography
	InitializeMpqCryptography();

	// We verify if the file already exists and if it's a MPQ archive.
	// If yes, we won't allow to overwrite it.
	if (SFileOpenArchive(pFactory, szMpqName, 0, STREAM_PROVIDER_FLAT | (pFactory ? BASE_PROVIDER_STREAM : BASE_PROVIDER_FILE) | MPQ_OPEN_NO_ATTRIBUTES | MPQ_OPEN_NO_LISTFILE, &hMpq))
	{
		SFileCloseArchive(hMpq);
		SetLastError(ERROR_ALREADY_EXISTS);
		return false;
	}

	//
	// At this point, we have to create the archive.
	// - If the file exists, convert it to MPQ archive.
	// - If the file doesn't exist, create new empty file
	//

	pStream = FileStream_OpenFile(pFactory, szMpqName, pCreateInfo->dwStreamFlags);
	if (pStream == NULL)
	{
		pStream = FileStream_CreateFile(pFactory, szMpqName, pCreateInfo->dwStreamFlags);
		if (pStream == NULL)
			return false;
	}

	// Increment the maximum amount of files to have space for (listfile)
	if (pCreateInfo->dwMaxFileCount && pCreateInfo->dwFileFlags1)
	{
		dwMpqFlags |= MPQ_FLAG_LISTFILE_NEW;
		dwReservedFiles++;
	}

	// Increment the maximum amount of files to have space for (attributes)
	if (pCreateInfo->dwMaxFileCount && pCreateInfo->dwFileFlags2 && pCreateInfo->dwAttrFlags)
	{
		dwMpqFlags |= MPQ_FLAG_ATTRIBUTES_NEW;
		dwReservedFiles++;
	}

	// Increment the maximum amount of files to have space for (signature)
	if (pCreateInfo->dwMaxFileCount && pCreateInfo->dwFileFlags3)
	{
		dwMpqFlags |= MPQ_FLAG_SIGNATURE_NEW;
		dwReservedFiles++;
	}

	// If file count is not zero, initialize the hash table size
	dwHashTableSize = GetNearestPowerOfTwo(pCreateInfo->dwMaxFileCount + dwReservedFiles);

	// Retrieve the file size and round it up to 0x200 bytes
	FileStream_GetSize(pStream, &MpqPos);
	MpqPos = (MpqPos + 0x1FF) & (ULONGLONG)0xFFFFFFFFFFFFFE00ULL;
	if (!FileStream_SetSize(pStream, MpqPos))
		nError = GetLastError();

#ifdef _DEBUG    
	// Debug code, used for testing StormLib
//  dwBlockTableSize = dwHashTableSize * 2;
#endif

	// Create the archive handle
	if (nError == ERROR_SUCCESS)
	{
		if ((ha = STORM_ALLOC(TMPQArchive, 1)) == NULL)
			nError = ERROR_NOT_ENOUGH_MEMORY;
	}

	// Fill the MPQ archive handle structure
	if (nError == ERROR_SUCCESS)
	{
		memset(ha, 0, sizeof(TMPQArchive));
		ha->pfnHashString = HashStringSlash;
		ha->pStream = pStream;
		ha->dwSectorSize = pCreateInfo->dwSectorSize;
		ha->UserDataPos = MpqPos;
		ha->MpqPos = MpqPos;
		ha->pHeader = pHeader = (TMPQHeader *)ha->HeaderData;
		ha->dwMaxFileCount = dwHashTableSize;
		ha->dwFileTableSize = 0;
		ha->dwReservedFiles = dwReservedFiles;
		ha->dwFileFlags1 = pCreateInfo->dwFileFlags1;
		ha->dwFileFlags2 = pCreateInfo->dwFileFlags2;
		ha->dwFileFlags3 = pCreateInfo->dwFileFlags3 ? MPQ_FILE_EXISTS : 0;
		ha->dwAttrFlags = pCreateInfo->dwAttrFlags;
		ha->dwFlags = dwMpqFlags | MPQ_FLAG_CHANGED;
		pStream = NULL;

		// Fill the MPQ header
		memset(pHeader, 0, sizeof(ha->HeaderData));
		pHeader->dwID = ID_MPQ;
		pHeader->dwHeaderSize = MpqHeaderSizes[pCreateInfo->dwMpqVersion];
		pHeader->dwArchiveSize = pHeader->dwHeaderSize + dwHashTableSize * sizeof(TMPQHash);
		pHeader->wFormatVersion = (USHORT)pCreateInfo->dwMpqVersion;
		pHeader->wSectorSize = GetSectorSizeShift(ha->dwSectorSize);
		pHeader->dwHashTablePos = pHeader->dwHeaderSize;
		pHeader->dwHashTableSize = dwHashTableSize;
		pHeader->dwBlockTablePos = pHeader->dwHashTablePos + dwHashTableSize * sizeof(TMPQHash);
		pHeader->dwBlockTableSize = dwBlockTableSize;

		// For MPQs version 4 and higher, we set the size of raw data block
		// for calculating MD5
		if (pCreateInfo->dwMpqVersion >= MPQ_FORMAT_VERSION_4)
			pHeader->dwRawChunkSize = pCreateInfo->dwRawChunkSize;

		// Write the naked MPQ header
		nError = WriteNakedMPQHeader(ha);
	}

	// Create initial HET table, if the caller required an MPQ format 3.0 or newer
	if (nError == ERROR_SUCCESS && pCreateInfo->dwMpqVersion >= MPQ_FORMAT_VERSION_3 && pCreateInfo->dwMaxFileCount != 0)
	{
		ha->pHetTable = CreateHetTable(ha->dwFileTableSize, 0, 0x40, NULL);
		if (ha->pHetTable == NULL)
			nError = ERROR_NOT_ENOUGH_MEMORY;
	}

	// Create initial hash table
	if (nError == ERROR_SUCCESS && dwHashTableSize != 0)
	{
		nError = CreateHashTable(ha, dwHashTableSize);
	}

	// Create initial file table
	if (nError == ERROR_SUCCESS && ha->dwMaxFileCount != 0)
	{
		nError = CreateFileTable(ha, ha->dwMaxFileCount);
	}

	// Cleanup : If an error, delete all buffers and return
	if (nError != ERROR_SUCCESS)
	{
		FileStream_Close(pStream);
		FreeArchiveHandle(ha);
		SetLastError(nError);
		ha = NULL;
	}

	// Return the values
	*phMpq = (HANDLE)ha;
	return (nError == ERROR_SUCCESS);
}
