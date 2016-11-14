#pragma once

#pragma managed(push, off)
#include <stormlib++.hpp>
#pragma managed(pop)

using namespace System;
using namespace System::Collections;
using namespace System::IO;
using namespace System::Runtime::Serialization;

namespace StormLib
{
	namespace Net
	{
		public ref class Constants abstract sealed
		{
		private:
			static String^ s_versionString = nullptr;
			static String^ s_listfileName = nullptr;
			static String^ s_signatureName = nullptr;
			static String^ s_attributesName = nullptr;
			static String^ s_patchMetadataName = nullptr;

		public:
			static property Int32 Version
			{
				Int32 get();
			}

			static property String^ VersionString
			{
				String^ get();
			}

			static property Int32 IdMpq
			{
				Int32 get();
			}

			static property Int32 IdMpqUserdata
			{
				Int32 get();
			}

			static property Int32 IdMpk
			{
				Int32 get();
			}

			static property Int32 HashTableSizeMin
			{
				Int32 get();
			}

			static property Int32 HashTableSizeDefault
			{
				Int32 get();
			}

			static property Int32 HashTableSizeMax
			{
				Int32 get();
			}

			static property String^ ListfileName
			{
				String^ get();
			}

			static property String^ SignatureName
			{
				String^ get();
			}

			static property String^ AttributesName
			{
				String^ get();
			}

			static property String^ PatchMetadataName
			{
				String^ get();
			}

			static property Int32 LanguageNeutral
			{
				Int32 get();
			}
		};

		[FlagsAttribute()]
		public enum class MpqFlag : Int32
		{
			None = static_cast<Int32>(stormlib::mpq_flag::none),
			ReadOnly = static_cast<Int32>(stormlib::mpq_flag::read_only),
			Changed = static_cast<Int32>(stormlib::mpq_flag::changed),
			Malformed = static_cast<Int32>(stormlib::mpq_flag::malformed),
			HashTableCut = static_cast<Int32>(stormlib::mpq_flag::hash_table_cut),
			BlockTableCut = static_cast<Int32>(stormlib::mpq_flag::block_table_cut),
			CheckSectorCrc = static_cast<Int32>(stormlib::mpq_flag::check_sector_crc),
			SavingTables = static_cast<Int32>(stormlib::mpq_flag::saving_tables),
			Patch = static_cast<Int32>(stormlib::mpq_flag::patch),
			War3Map = static_cast<Int32>(stormlib::mpq_flag::war3map),
			ListfileNone = static_cast<Int32>(stormlib::mpq_flag::listfile_none),
			ListfileNew = static_cast<Int32>(stormlib::mpq_flag::listfile_new),
			AttributesNone = static_cast<Int32>(stormlib::mpq_flag::attributes_none),
			AttributesNew = static_cast<Int32>(stormlib::mpq_flag::attributes_new),
			SignatureNone = static_cast<Int32>(stormlib::mpq_flag::signature_none),
			SignatureNew = static_cast<Int32>(stormlib::mpq_flag::signature_new),
		};

		[FlagsAttribute()]
		public enum class FileFlag : Int32
		{
			None = static_cast<Int32>(stormlib::file_flag::none),
			Implode = static_cast<Int32>(stormlib::file_flag::implode),
			Compress = static_cast<Int32>(stormlib::file_flag::compress),
			Encrypted = static_cast<Int32>(stormlib::file_flag::encrypted),
			FixKey = static_cast<Int32>(stormlib::file_flag::fix_key),
			PatchFile = static_cast<Int32>(stormlib::file_flag::patch_file),
			SingleUnit = static_cast<Int32>(stormlib::file_flag::single_unit),
			DeleteMarker = static_cast<Int32>(stormlib::file_flag::delete_marker),
			SectorCrc = static_cast<Int32>(stormlib::file_flag::sector_crc),
			Signature = static_cast<Int32>(stormlib::file_flag::signature),
			Exists = static_cast<Int32>(stormlib::file_flag::exists),
			ReplaceExisting = static_cast<Int32>(stormlib::file_flag::replace_existing),
			CompressMask = static_cast<Int32>(stormlib::file_flag::compress_mask),
			ValidFlags = static_cast<Int32>(stormlib::file_flag::valid_flags),
		};

		[FlagsAttribute()]
		public enum class AddFileFlag : Int32
		{
			None = static_cast<Int32>(stormlib::add_file_flag::none),
			Implode = static_cast<Int32>(stormlib::add_file_flag::implode),
			Compress = static_cast<Int32>(stormlib::add_file_flag::compress),
			Encrypted = static_cast<Int32>(stormlib::add_file_flag::encrypted),
			FixKey = static_cast<Int32>(stormlib::add_file_flag::fix_key),
			DeleteMarker = static_cast<Int32>(stormlib::add_file_flag::delete_marker),
			SectorCrc = static_cast<Int32>(stormlib::add_file_flag::sector_crc),
			SingleUnit = static_cast<Int32>(stormlib::add_file_flag::single_unit),
			ReplaceExisting = static_cast<Int32>(stormlib::add_file_flag::replace_existing),
		};

		[FlagsAttribute()]
		public enum class CompressionFlag : Int32
		{
			None = static_cast<Int32>(stormlib::compression_flag::none),
			Huffman = static_cast<Int32>(stormlib::compression_flag::huffman),
			ZLib = static_cast<Int32>(stormlib::compression_flag::zlib),
			PKWare = static_cast<Int32>(stormlib::compression_flag::pkware),
			BZip2 = static_cast<Int32>(stormlib::compression_flag::bzip2),
			Sparse = static_cast<Int32>(stormlib::compression_flag::sparse),
			AdpcmMono = static_cast<Int32>(stormlib::compression_flag::adpcm_mono),
			AdpcmStereo = static_cast<Int32>(stormlib::compression_flag::adpcm_stereo),
			Lzma = static_cast<Int32>(stormlib::compression_flag::lzma),
		};

		public enum class MpqFormatVersion : Int32
		{
			_1 = static_cast<Int32>(stormlib::mpq_format_version::_1),
			_2 = static_cast<Int32>(stormlib::mpq_format_version::_2),
			_3 = static_cast<Int32>(stormlib::mpq_format_version::_3),
			_4 = static_cast<Int32>(stormlib::mpq_format_version::_4),
		};

		[FlagsAttribute()]
		public enum class AttributeFlag : Int32
		{
			None = static_cast<Int32>(stormlib::attribute_flag::none),
			Crc32 = static_cast<Int32>(stormlib::attribute_flag::crc32),
			FileTime = static_cast<Int32>(stormlib::attribute_flag::file_time),
			MD5 = static_cast<Int32>(stormlib::attribute_flag::md5),
			PatchBit = static_cast<Int32>(stormlib::attribute_flag::patch_bit),
			All = static_cast<Int32>(stormlib::attribute_flag::all),
		};

		public enum class BaseProvider : Int32
		{
			File = static_cast<Int32>(stormlib::base_provider::file),
			Map = static_cast<Int32>(stormlib::base_provider::map),
			Http = static_cast<Int32>(stormlib::base_provider::http),
			Stream = static_cast<Int32>(stormlib::base_provider::stream),
		};

		public enum class StreamProvider : Int32
		{
			Flat = static_cast<Int32>(stormlib::stream_provider::flat),
			Partial = static_cast<Int32>(stormlib::stream_provider::partial),
			MPQE = static_cast<Int32>(stormlib::stream_provider::mpqe),
			Block4 = static_cast<Int32>(stormlib::stream_provider::block4),
		};

		[FlagsAttribute()]
		public enum class StreamFlag : Int32
		{
			None = static_cast<Int32>(stormlib::stream_flag::none),
			ReadOnly = static_cast<Int32>(stormlib::stream_flag::read_only),
			WriteShare = static_cast<Int32>(stormlib::stream_flag::write_share),
			UseBitmap = static_cast<Int32>(stormlib::stream_flag::use_bitmap),
		};

		[FlagsAttribute()]
		public enum class MpqOpenFlag : Int32
		{
			None = static_cast<Int32>(stormlib::mpq_open_flag::none),
			NoListfile = static_cast<Int32>(stormlib::mpq_open_flag::no_listfile),
			NoAttributes = static_cast<Int32>(stormlib::mpq_open_flag::no_attributes),
			NoHeaderSearch = static_cast<Int32>(stormlib::mpq_open_flag::no_header_search),
			ForceMPQv1 = static_cast<Int32>(stormlib::mpq_open_flag::force_mpq_v1),
			CheckSectorCrc = static_cast<Int32>(stormlib::mpq_open_flag::check_sector_crc),
		};

		[FlagsAttribute()]
		public enum class MpqCreateFlag : Int32
		{
			None = static_cast<Int32>(stormlib::mpq_create_flag::none),
			CreateListfile = static_cast<Int32>(stormlib::mpq_create_flag::create_listfile),
			CreateAttributes = static_cast<Int32>(stormlib::mpq_create_flag::create_attributes),
			CreateSignature = static_cast<Int32>(stormlib::mpq_create_flag::create_signature),
			Version1 = static_cast<Int32>(stormlib::mpq_create_flag::version_1),
			Version2 = static_cast<Int32>(stormlib::mpq_create_flag::version_2),
			Version3 = static_cast<Int32>(stormlib::mpq_create_flag::version_3),
			Version4 = static_cast<Int32>(stormlib::mpq_create_flag::version_4),
			VersionMask = static_cast<Int32>(stormlib::mpq_create_flag::version_mask),
		};

		[FlagsAttribute()]
		public enum class VerifyFileFlag : Int32
		{
			None = static_cast<Int32>(stormlib::verify_file_flag::none),
			SectorCrc = static_cast<Int32>(stormlib::verify_file_flag::sector_crc),
			FileCrc = static_cast<Int32>(stormlib::verify_file_flag::file_crc),
			FileMD5 = static_cast<Int32>(stormlib::verify_file_flag::file_md5),
			RawMD5 = static_cast<Int32>(stormlib::verify_file_flag::raw_md5),
			All = static_cast<Int32>(stormlib::verify_file_flag::all),
		};

		public enum class SignatureType : Int32
		{
			None = static_cast<Int32>(stormlib::signature_type::none),
			Weak = static_cast<Int32>(stormlib::signature_type::weak),
			Strong = static_cast<Int32>(stormlib::signature_type::strong),
		};

		[FlagsAttribute()]
		public enum class VerifyFileResultFlag : Int32
		{
			None = static_cast<Int32>(stormlib::verify_file_result_flag::none),
			OpenError = static_cast<Int32>(stormlib::verify_file_result_flag::open_error),
			ReadError = static_cast<Int32>(stormlib::verify_file_result_flag::read_error),
			HasSectorCrc = static_cast<Int32>(stormlib::verify_file_result_flag::has_sector_crc),
			SectorCrcError = static_cast<Int32>(stormlib::verify_file_result_flag::sector_crc_error),
			HasChecksum = static_cast<Int32>(stormlib::verify_file_result_flag::has_checksum),
			ChecksumError = static_cast<Int32>(stormlib::verify_file_result_flag::checksum_error),
			HasMD5 = static_cast<Int32>(stormlib::verify_file_result_flag::has_md5),
			MD5Error = static_cast<Int32>(stormlib::verify_file_result_flag::md5_error),
			HasRawMD5 = static_cast<Int32>(stormlib::verify_file_result_flag::has_raw_md5),
			RawMD5Error = static_cast<Int32>(stormlib::verify_file_result_flag::raw_md5_error),
			ErrorMask = static_cast<Int32>(stormlib::verify_file_result_flag::error_mask),
		};

		public enum class VerifyArchiveResult : Int32
		{
			NoSignature = static_cast<Int32>(stormlib::verify_archive_result::no_signature),
			VerifyFailed = static_cast<Int32>(stormlib::verify_archive_result::verify_failed),
			WeakSignatureOk = static_cast<Int32>(stormlib::verify_archive_result::weak_signature_ok),
			WeakSignatureError = static_cast<Int32>(stormlib::verify_archive_result::weak_signature_error),
			StrongSignatureOk = static_cast<Int32>(stormlib::verify_archive_result::strong_signature_ok),
			StrongSignatureError = static_cast<Int32>(stormlib::verify_archive_result::strong_signature_error),
		};

		public enum class ArchiveEnumerationType : Int32
		{
			Archive,
			Listfile,
		};

		public delegate void AddFileCallback(Int32 bytesWritten, Int32 totalBytes, Boolean finalCall);
		public delegate void CompactProgressCallback(Int64 current, Int64 total);

		public ref class CompactCallback sealed
		{
		public:
			property CompactProgressCallback^ CheckingFiles;
			property CompactProgressCallback^ CheckingHashTable;
			property CompactProgressCallback^ CopyingNonMpqData;
			property CompactProgressCallback^ CompactingArchve;
			property CompactProgressCallback^ ClosingArchive;
		};

		public ref class CreateMpq sealed
		{
		public:
			property MpqFormatVersion Version;
			property BaseProvider BaseProvider;
			property StreamProvider StreamProvider;
			property StreamFlag StreamFlags;
			property FileFlag ListfileFlags;
			property FileFlag AttributesFlags;
			property FileFlag SignatureFlags;
			property AttributeFlag FileAttributes;
			property Int32 SectorSize;
			property Int32 RawChunkSize;
			property Int32 MaxFileCount;

			CreateMpq();
		};

		public interface class IStreamProvider
		{
		public:
			Int32 Read(Int64 streamOffset, IntPtr buffer, Int32 toRead);
			Int32 Write(Int64 streamOffset, IntPtr buffer, Int32 toWrite);
			void Resize(Int64 newSize);
		};

		public interface class IStreamProviderFactory
		{
		public:
			IStreamProvider^ Create(String^ fileName, Boolean shareWrite);
			void Open(String^ fileName, Boolean readOnly, Boolean shareWrite, IStreamProvider^% stream, Int64% fileSize, DateTime% fileTime);
			void Close(IStreamProvider^ stream);
		};

		struct raw_stream_provider_wrapper;
		struct raw_stream_provider_factory_wrapper;

		private ref class ExceptionContext sealed
		{
		private:
			Generic::List<Exception^>^ m_exceptions;

		public:
			ExceptionContext();

			UInt32 Add(Exception^ ex);
			void ThrowException(Exception^ ex);
			void Check();
		};

		public ref class Archive sealed
		{
		private:
			raw_stream_provider_factory_wrapper* m_factory;
			ExceptionContext^ m_context;
			HANDLE m_handle;
			CompactCallback^ m_compactCallback;
			AddFileCallback^ m_addFileCallback;
			String^ m_fileName;

			Archive(IStreamProviderFactory^ factory);

		internal:
			property ExceptionContext^ Context
			{
				ExceptionContext^ get();
			}

		public:
			!Archive();
			~Archive();

			static Int32 GetLocale();
			static Int32 SetLocale(Int32 newLocale);

			static Archive^ Open(IStreamProviderFactory^ factory, String^ mpqName, BaseProvider baseProvider, StreamProvider streamProvider, StreamFlag streamFlags, MpqOpenFlag flags);
			static Archive^ Create(IStreamProviderFactory^ factory, String^ mpqName, MpqCreateFlag flags, Int32 maxFileCount);
			static Archive^ Create(IStreamProviderFactory^ factory, String^ mpqName, CreateMpq^ data);

			property CompactCallback^ CompactCallback
			{
				StormLib::Net::CompactCallback^ get();
				void set(StormLib::Net::CompactCallback^ value);
			}

			property AddFileCallback^ AddFileCallback
			{
				StormLib::Net::AddFileCallback^ get();
				void set(StormLib::Net::AddFileCallback^ value);
			}

			property Int32 MaxFileCount
			{
				Int32 get();
				void set(Int32 value);
			}

			property AttributeFlag Attributes
			{
				AttributeFlag get();
				void set(AttributeFlag value);
			}

			property Boolean IsPatched
			{
				Boolean get();
			}

			property String^ FileName
			{
				String^ get();
			}

			property Int64 UserDataOffset
			{
				Int64 get();
			}

			property array<Byte>^ UserData
			{
				array<Byte>^ get();
			}

			property Int64 HeaderOffset
			{
				Int64 get();
			}

			property Int32 HeaderSize
			{
				Int32 get();
			}

			property Int64 HetTableOffset
			{
				Int64 get();
			}

			property Int64 HetTableSize
			{
				Int64 get();
			}

			property Int64 BetTableOffset
			{
				Int64 get();
			}

			property Int64 BetTableSize
			{
				Int64 get();
			}

			property Int64 HashTableOffset
			{
				Int64 get();
			}

			property Int64 HashTableSize64
			{
				Int64 get();
			}

			property Int32 HashTableSize
			{
				Int32 get();
			}

			property Int64 BlockTableOffset
			{
				Int64 get();
			}

			property Int64 BlockTableSize64
			{
				Int64 get();
			}

			property Int32 BlockTableSize
			{
				Int32 get();
			}

			property Int64 HiBlockTableOffset
			{
				Int64 get();
			}

			property Int64 HiBlockTableSize64
			{
				Int64 get();
			}

			property SignatureType Signatures
			{
				SignatureType get();
			}

			property Int64 StrongSignatureOffset
			{
				Int64 get();
			}

			property Int32 StrongSignatureSize
			{
				Int32 get();
			}

			property array<Byte>^ StrongSignature
			{
				array<Byte>^ get();
			}

			property Int64 ArchiveSize64
			{
				Int64 get();
			}

			property Int32 ArchiveSize
			{
				Int32 get();
			}

			property Int32 FileTableSize
			{
				Int32 get();
			}

			property Int32 SectorSize
			{
				Int32 get();
			}

			property Int32 NumberOfFiles
			{
				Int32 get();
			}

			property Int32 RawChunkSize
			{
				Int32 get();
			}

			property StreamFlag StreamFlags
			{
				StreamFlag get();
			}

			property BaseProvider BaseProvider
			{
				Net::BaseProvider get();
			}

			property MpqFlag Flags
			{
				MpqFlag get();
			}

			property IntPtr Handle
			{
				IntPtr get();
			}

			void Flush();
			void AddListFile(String^ listFile);
			void CompactArchive(String^ listFile);
			void UpdateFileAttributes(String^ fileName);
			void OpenPatchArchive(String^ patchMpqName, String^ patchPrefix);
			Boolean HasFile(String^ fileName);
			void ExtractFile(String^ toExtract, String^ extracted);
			VerifyFileResultFlag VerifyFile(String^ fileName, VerifyFileFlag flags);
			void Sign();
			VerifyArchiveResult Verify();
			array<Int32>^ EnumLocales(String^ fileName);
			void AddFile(String^ fileName, String^ archivedName, AddFileFlag flags, CompressionFlag compression, CompressionFlag nextCompression);
			void AddFile(String^ fileName, String^ archivedName, AddFileFlag flags, CompressionFlag compression);
			void RemoveFile(String^ fileName);
			void RenameFile(String^ oldFileName, String^ newFileName);
		};

		public ref class ArchiveReadFile sealed : public Stream
		{
		private:
			Archive^ m_archive;
			HANDLE m_handle;
			String^ m_fileName;
			String^ m_patchChain;

		internal:
			property ExceptionContext^ Context
			{
				ExceptionContext^ get();
			}

		public:
			ArchiveReadFile(Archive^ archive, String^ fileName);
			ArchiveReadFile(String^ fileName);
			!ArchiveReadFile();
			~ArchiveReadFile();

			property Archive^ Archive
			{
				Net::Archive^ get();
			}

			property IntPtr Handle
			{
				IntPtr get();
			}

			property Int64 FileSize
			{
				Int64 get();
			}

			property Int64 FilePointer
			{
				Int64 get();
				void set(Int64 value);
			}

			property Int32 Locale
			{
				Int32 get();
				void set(Int32 value);
			}

			property String^ FileName
			{
				String^ get();
			}

			property String^ PatchChain
			{
				String^ get();
			}

			property Int32 HashIndex
			{
				Int32 get();
			}

			property Int32 NameHash1
			{
				Int32 get();
			}

			property Int32 NameHash2
			{
				Int32 get();
			}

			property Int64 NameHash3
			{
				Int64 get();
			}

			property Int32 FileIndex
			{
				Int32 get();
			}

			property Int64 ByteOffset
			{
				Int64 get();
			}

			property DateTime FileTime
			{
				DateTime get();
			}

			property Int32 CompressedSize
			{
				Int32 get();
			}

			property FileFlag Flags
			{
				FileFlag get();
			}

			property Int32 EncryptionKey
			{
				Int32 get();
			}

			property Int32 EncryptionKeyRaw
			{
				Int32 get();
			}

			property Boolean CanRead
			{
				virtual Boolean get() override;
			}

			property Boolean CanSeek
			{
				virtual Boolean get() override;
			}

			property Boolean CanWrite
			{
				virtual Boolean get() override;
			}

			property Int64 Length
			{
				virtual Int64 get() override;
			}

			property Int64 Position
			{
				virtual Int64 get() override;
				virtual void set(Int64 value) override;
			}

			virtual void Flush() override;
			virtual Int64 Seek(Int64 offset, SeekOrigin origin) override;
			virtual void SetLength(Int64 value) override;
			virtual Int32 Read(array<Byte>^ buffer, Int32 offset, Int32 count) override;
			virtual void Write(array<Byte>^ buffer, Int32 offset, Int32 count) override;
		};

		public ref class ArchiveWriteFile sealed : public Stream
		{
		private:
			Archive^ m_archive;
			HANDLE m_handle;
			String^ m_fileName;
			DateTime m_fileTime;
			Int32 m_fileSize;
			Int32 m_filePointer;
			Int32 m_locale;
			CompressionFlag m_compression;

		internal:
			property ExceptionContext^ Context
			{
				ExceptionContext^ get();
			}

		public:
			ArchiveWriteFile(Archive^ archive, String^ fileName, DateTime fileTime, Int32 fileSize, Int32 locale, AddFileFlag flags);
			!ArchiveWriteFile();
			~ArchiveWriteFile();

			property Archive^ Archive
			{
				Net::Archive^ get();
			}

			property IntPtr Handle
			{
				IntPtr get();
			}

			property Int32 FileSize
			{
				Int32 get();
			}

			property Int32 FilePointer
			{
				Int32 get();
			}

			property Int32 Locale
			{
				Int32 get();
			}

			property String^ FileName
			{
				String^ get();
			}

			property CompressionFlag Compression
			{
				CompressionFlag get();
				void set(CompressionFlag value);
			}

			property Boolean CanRead
			{
				virtual Boolean get() override;
			}

			property Boolean CanSeek
			{
				virtual Boolean get() override;
			}

			property Boolean CanWrite
			{
				virtual Boolean get() override;
			}

			property Int64 Length
			{
				virtual Int64 get() override;
			}

			property Int64 Position
			{
				virtual Int64 get() override;
				virtual void set(Int64 value) override;
			}

			virtual void Flush() override;
			virtual Int64 Seek(Int64 offset, SeekOrigin origin) override;
			virtual void SetLength(Int64 value) override;
			virtual Int32 Read(array<Byte> ^buffer, Int32 offset, Int32 count) override;
			virtual void Write(array<Byte> ^buffer, Int32 offset, Int32 count) override;
		};

		public interface class IArchiveEnumerator
		{
		public:
			property Archive^ Archive
			{
				Net::Archive^ get();
			}

			property IntPtr Handle
			{
				IntPtr get();
			}

			property Boolean IsValid
			{
				Boolean get();
			}

			property String^ FileName
			{
				String^ get();
			}

			property String^ PlainName
			{
				String^ get();
			}

			property Int32 HashIndex
			{
				Int32 get();
			}

			property Int32 BlockIndex
			{
				Int32 get();
			}

			property Int32 FileSize
			{
				Int32 get();
			}

			property FileFlag Flags
			{
				FileFlag get();
			}

			property Int32 CompressedSize
			{
				Int32 get();
			}

			property DateTime FileTime
			{
				DateTime get();
			}

			property Int32 Locale
			{
				Int32 get();
			}

			void Next();
		};

		public ref class ArchiveEnumerator sealed : public IArchiveEnumerator
		{
		private:
			Archive^ m_archive;
			HANDLE m_handle;
			SFILE_FIND_DATA* m_findData;
			String^ m_fileName;
			String^ m_plainName;

		internal:
			property ExceptionContext^ Context
			{
				ExceptionContext^ get();
			}

		public:
			ArchiveEnumerator(Archive^ archive, String^ mask, String^ listFile);
			ArchiveEnumerator(Archive^ archive, String^ listFile);
			ArchiveEnumerator(Archive^ archive);
			!ArchiveEnumerator();
			~ArchiveEnumerator();

			property Archive^ Archive
			{
				virtual Net::Archive^ get();
			}

			property IntPtr Handle
			{
				virtual IntPtr get();
			}

			property Boolean IsValid
			{
				virtual Boolean get();
			}

			property String^ FileName
			{
				virtual String^ get();
			}

			property String^ PlainName
			{
				virtual String^ get();
			}

			property Int32 HashIndex
			{
				virtual Int32 get();
			}

			property Int32 BlockIndex
			{
				virtual Int32 get();
			}

			property Int32 FileSize
			{
				virtual Int32 get();
			}

			property FileFlag Flags
			{
				virtual FileFlag get();
			}

			property Int32 CompressedSize
			{
				virtual Int32 get();
			}

			property DateTime FileTime
			{
				virtual DateTime get();
			}

			property Int32 Locale
			{
				virtual Int32 get();
			}

			virtual void Next();
		};

		public ref class ListfileEnumerator sealed : public IArchiveEnumerator
		{
		private:
			Archive^ m_archive;
			HANDLE m_handle;
			SFILE_FIND_DATA* m_findData;
			String^ m_fileName;
			String^ m_plainName;

		internal:
			property ExceptionContext^ Context
			{
				ExceptionContext^ get();
			}

		public:
			ListfileEnumerator(Archive^ archive, String^ mask, String^ listFile);
			ListfileEnumerator(Archive^ archive, String^ listFile);
			ListfileEnumerator(Archive^ archive);
			!ListfileEnumerator();
			~ListfileEnumerator();

			property Archive^ Archive
			{
				virtual Net::Archive^ get();
			}

			property IntPtr Handle
			{
				virtual IntPtr get();
			}

			property Boolean IsValid
			{
				virtual Boolean get();
			}

			property String^ FileName
			{
				virtual String^ get();
			}

			property String^ PlainName
			{
				virtual String^ get();
			}

			property Int32 HashIndex
			{
				virtual Int32 get();
			}

			property Int32 BlockIndex
			{
				virtual Int32 get();
			}

			property Int32 FileSize
			{
				virtual Int32 get();
			}

			property FileFlag Flags
			{
				virtual FileFlag get();
			}

			property Int32 CompressedSize
			{
				virtual Int32 get();
			}

			property DateTime FileTime
			{
				virtual DateTime get();
			}

			property Int32 Locale
			{
				virtual Int32 get();
			}

			virtual void Next();
		};

		public ref class ArchiveFileInfo
		{
		private:
			Archive^ m_archive;
			String^ m_fileName;
			String^ m_plainName;
			Int32 m_hashIndex;
			Int32 m_blockIndex;
			Int32 m_fileSize;
			FileFlag m_flags;
			Int32 m_compressedSize;
			DateTime m_fileTime;
			Int32 m_locale;

		internal:
			ArchiveFileInfo(IArchiveEnumerator^ enumerator);

		public:
			property Archive^ Archive
			{
				Net::Archive^ get();
			}

			property String^ FileName
			{
				String^ get();
			}

			property String^ PlainName
			{
				String^ get();
			}

			property Int32 HashIndex
			{
				Int32 get();
			}

			property Int32 BlockIndex
			{
				Int32 get();
			}

			property Int32 FileSize
			{
				Int32 get();
			}

			property FileFlag Flags
			{
				FileFlag get();
			}

			property Int32 CompressedSize
			{
				Int32 get();
			}

			property DateTime FileTime
			{
				DateTime get();
			}

			property Int32 Locale
			{
				Int32 get();
			}
		};

		public ref class ArchiveFileCollection : public Generic::IEnumerable<ArchiveFileInfo^>, public IEnumerable
		{
		private:
			ref class Enumerator;

			IArchiveEnumerator^ m_enumerator;
			Generic::List<ArchiveFileInfo^>^ m_info;

			Boolean UpdateNext(Int32 index);
			ArchiveFileInfo^ Get(Int32 index);

		public:
			ArchiveFileCollection(Archive^ archive, ArchiveEnumerationType type);
			ArchiveFileCollection(Archive^ archive, String^ listFile, ArchiveEnumerationType type);
			ArchiveFileCollection(Archive^ archive, String^ mask, String^ listFile, ArchiveEnumerationType type);
			ArchiveFileCollection(IArchiveEnumerator^ enumerator);
			~ArchiveFileCollection();

			property Archive^ Archive
			{
				Net::Archive^ get();
			}

			virtual Generic::IEnumerator<ArchiveFileInfo^>^ GetEnumerator() = Generic::IEnumerable<ArchiveFileInfo^>::GetEnumerator;

			virtual IEnumerator^ EnumerableGetEnumerator() = IEnumerable::GetEnumerator;
		};

		[Serializable]
		public ref class AviFileException : public IOException
		{
		public:
			AviFileException();
			AviFileException(String^ message);
			AviFileException(String^ message, Exception^ inner);

		protected:
			AviFileException(SerializationInfo^ info, StreamingContext context);
		};

		[Serializable]
		public ref class UnknownFileKeyException : public IOException
		{
		public:
			UnknownFileKeyException();
			UnknownFileKeyException(String^ message);
			UnknownFileKeyException(String^ message, Exception^ inner);

		protected:
			UnknownFileKeyException(SerializationInfo^ info, StreamingContext context);
		};

		[Serializable]
		public ref class ChecksumErrorException : public IOException
		{
		public:
			ChecksumErrorException();
			ChecksumErrorException(String^ message);
			ChecksumErrorException(String^ message, Exception^ inner);

		protected:
			ChecksumErrorException(SerializationInfo^ info, StreamingContext context);
		};

		[Serializable]
		public ref class InternalFileException : public IOException
		{
		public:
			InternalFileException();
			InternalFileException(String^ message);
			InternalFileException(String^ message, Exception^ inner);

		protected:
			InternalFileException(SerializationInfo^ info, StreamingContext context);
		};

		[Serializable]
		public ref class BaseFileMissingException : public IOException
		{
		public:
			BaseFileMissingException();
			BaseFileMissingException(String^ message);
			BaseFileMissingException(String^ message, Exception^ inner);

		protected:
			BaseFileMissingException(SerializationInfo^ info, StreamingContext context);
		};

		[Serializable]
		public ref class MarkedForDeleteException : public IOException
		{
		public:
			MarkedForDeleteException();
			MarkedForDeleteException(String^ message);
			MarkedForDeleteException(String^ message, Exception^ inner);

		protected:
			MarkedForDeleteException(SerializationInfo^ info, StreamingContext context);
		};

		[Serializable]
		public ref class FileIncompleteException : public IOException
		{
		public:
			FileIncompleteException();
			FileIncompleteException(String^ message);
			FileIncompleteException(String^ message, Exception^ inner);

		protected:
			FileIncompleteException(SerializationInfo^ info, StreamingContext context);
		};

		[Serializable]
		public ref class UnknownFileNamesException : public IOException
		{
		public:
			UnknownFileNamesException();
			UnknownFileNamesException(String^ message);
			UnknownFileNamesException(String^ message, Exception^ inner);

		protected:
			UnknownFileNamesException(SerializationInfo^ info, StreamingContext context);
		};

		[Serializable]
		public ref class CantFindPatchPrefixException : public IOException
		{
		public:
			CantFindPatchPrefixException();
			CantFindPatchPrefixException(String^ message);
			CantFindPatchPrefixException(String^ message, Exception^ inner);

		protected:
			CantFindPatchPrefixException(SerializationInfo^ info, StreamingContext context);
		};

		[Serializable]
		public ref class ExceptionLostException : public Exception
		{
		public:
			ExceptionLostException();
			ExceptionLostException(String^ message);
			ExceptionLostException(String^ message, Exception^ inner);

		protected:
			ExceptionLostException(SerializationInfo^ info, StreamingContext context);
		};
	}
}
