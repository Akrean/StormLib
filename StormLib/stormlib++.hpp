#pragma once

#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include "StormLib.h"

#define STORMLIB_PP_FLAGS(type) \
	inline constexpr type operator~(type v) { return ::stormlib::internal::flags<type>::not_impl(v); } \
	inline constexpr type operator&(type x, type y) { return ::stormlib::internal::flags<type>::and_impl(x, y); } \
	inline constexpr type operator|(type x, type y) { return ::stormlib::internal::flags<type>::or_impl(x, y); } \
	inline constexpr type operator^(type x, type y) { return ::stormlib::internal::flags<type>::xor_impl(x, y); } \
	inline type& operator&=(type& x, type y) { return x = ::stormlib::internal::flags<type>::and_impl(x, y); } \
	inline type& operator|=(type& x, type y) { return x = ::stormlib::internal::flags<type>::or_impl(x, y); } \
	inline type& operator^=(type& x, type y) { return x = ::stormlib::internal::flags<type>::xor_impl(x, y); } \
	inline constexpr bool has_any(type f, type check) { return ::stormlib::internal::flags<type>::has_any(f, check); } \
	inline constexpr bool has_all(type f, type check) { return ::stormlib::internal::flags<type>::has_all(f, check); }

namespace stormlib
{
	typedef std::basic_string<CHAR> astring;
	typedef std::basic_string<WCHAR> wstring;
	typedef std::basic_string<TCHAR> tstring;

	typedef const CHAR* a_cstr;
	typedef const WCHAR* w_cstr;
	typedef const TCHAR* t_cstr;

	namespace internal
	{
		template<typename T>
		struct flags
		{
			static_assert(std::is_enum<T>::value, "T must be an enum");

		private:
			typedef std::underlying_type_t<T> int_t;

			inline static constexpr int_t to_int(T value)
			{
				return static_cast<int_t>(value);
			}

			inline static constexpr T from_int(int_t value)
			{
				return static_cast<T>(value);
			}

		public:
			inline static constexpr T and_impl(T x, T y)
			{
				return from_int(to_int(x) & to_int(y));
			}

			inline static constexpr T or_impl(T x, T y)
			{
				return from_int(to_int(x) | to_int(y));
			}

			inline static constexpr T xor_impl(T x, T y)
			{
				return from_int(to_int(x) ^ to_int(y));
			}

			inline static constexpr T not_impl(T v)
			{
				return from_int(~to_int(v));
			}

			inline static constexpr bool has_any(T f, T check)
			{
				return (to_int(f) & to_int(check)) != 0;
			}

			inline static constexpr bool has_all(T f, T check)
			{
				return (to_int(f) & to_int(check)) == to_int(check);
			}
		};
	}

	constexpr std::uint32_t version = STORMLIB_VERSION;
	constexpr const char* version_string = STORMLIB_VERSION_STRING;
	constexpr std::uint32_t id_mpq = ID_MPQ;
	constexpr std::uint32_t id_mpq_userdata = ID_MPQ_USERDATA;
	constexpr std::uint32_t id_mpk = ID_MPK;
	constexpr std::uint32_t hash_table_size_min = HASH_TABLE_SIZE_MIN;
	constexpr std::uint32_t hash_table_size_default = HASH_TABLE_SIZE_DEFAULT;
	constexpr std::uint32_t hash_table_size_max = HASH_TABLE_SIZE_MAX;
	constexpr const char* listfile_name = LISTFILE_NAME;
	constexpr const char* signature_name = SIGNATURE_NAME;
	constexpr const char* attributes_name = ATTRIBUTES_NAME;
	constexpr const char* patch_metadata_name = PATCH_METADATA_NAME;
	constexpr LCID language_neutral = LANG_NEUTRAL;

	enum class mpq_flag : std::uint32_t
	{
		none = 0,
		read_only = MPQ_FLAG_READ_ONLY,
		changed = MPQ_FLAG_CHANGED,
		malformed = MPQ_FLAG_MALFORMED,
		hash_table_cut = MPQ_FLAG_HASH_TABLE_CUT,
		block_table_cut = MPQ_FLAG_BLOCK_TABLE_CUT,
		check_sector_crc = MPQ_FLAG_CHECK_SECTOR_CRC,
		saving_tables = MPQ_FLAG_SAVING_TABLES,
		patch = MPQ_FLAG_PATCH,
		war3map = MPQ_FLAG_WAR3_MAP,
		listfile_none = MPQ_FLAG_LISTFILE_NONE,
		listfile_new = MPQ_FLAG_LISTFILE_NEW,
		attributes_none = MPQ_FLAG_ATTRIBUTES_NONE,
		attributes_new = MPQ_FLAG_ATTRIBUTES_NEW,
		signature_none = MPQ_FLAG_SIGNATURE_NONE,
		signature_new = MPQ_FLAG_SIGNATURE_NEW,
	};

	STORMLIB_PP_FLAGS(mpq_flag);

	enum class file_flag : std::uint32_t
	{
		none = 0,
		implode = MPQ_FILE_IMPLODE,
		compress = MPQ_FILE_COMPRESS,
		encrypted = MPQ_FILE_ENCRYPTED,
		fix_key = MPQ_FILE_FIX_KEY,
		patch_file = MPQ_FILE_PATCH_FILE,
		single_unit = MPQ_FILE_SINGLE_UNIT,
		delete_marker = MPQ_FILE_DELETE_MARKER,
		sector_crc = MPQ_FILE_SECTOR_CRC,
		signature = MPQ_FILE_SIGNATURE,
		exists = MPQ_FILE_EXISTS,
		replace_existing = MPQ_FILE_REPLACEEXISTING,
		compress_mask = MPQ_FILE_COMPRESS_MASK,
		valid_flags = MPQ_FILE_VALID_FLAGS,
	};

	STORMLIB_PP_FLAGS(file_flag);

	enum class add_file_flag : std::uint32_t
	{
		none = 0,
		implode = MPQ_FILE_IMPLODE,
		compress = MPQ_FILE_COMPRESS,
		encrypted = MPQ_FILE_ENCRYPTED,
		fix_key = MPQ_FILE_FIX_KEY,
		delete_marker = MPQ_FILE_DELETE_MARKER,
		sector_crc = MPQ_FILE_SECTOR_CRC,
		single_unit = MPQ_FILE_SINGLE_UNIT,
		replace_existing = MPQ_FILE_REPLACEEXISTING,
	};

	STORMLIB_PP_FLAGS(add_file_flag);

	enum class compression_flag : std::uint32_t
	{
		none = 0,
		huffman = MPQ_COMPRESSION_HUFFMANN,
		zlib = MPQ_COMPRESSION_ZLIB,
		pkware = MPQ_COMPRESSION_PKWARE,
		bzip2 = MPQ_COMPRESSION_BZIP2,
		sparse = MPQ_COMPRESSION_SPARSE,
		adpcm_mono = MPQ_COMPRESSION_ADPCM_MONO,
		adpcm_stereo = MPQ_COMPRESSION_ADPCM_STEREO,
		lzma = MPQ_COMPRESSION_LZMA,
	};

	STORMLIB_PP_FLAGS(compression_flag);

	enum class mpq_format_version : std::uint32_t
	{
		_1 = MPQ_FORMAT_VERSION_1,
		_2 = MPQ_FORMAT_VERSION_2,
		_3 = MPQ_FORMAT_VERSION_3,
		_4 = MPQ_FORMAT_VERSION_4,
	};

	enum class attribute_flag : std::uint32_t
	{
		none = 0,
		crc32 = MPQ_ATTRIBUTE_CRC32,
		file_time = MPQ_ATTRIBUTE_FILETIME,
		md5 = MPQ_ATTRIBUTE_MD5,
		patch_bit = MPQ_ATTRIBUTE_PATCH_BIT,
		all = MPQ_ATTRIBUTE_ALL,
	};

	STORMLIB_PP_FLAGS(attribute_flag);

	enum class base_provider : std::uint32_t
	{
		file = BASE_PROVIDER_FILE,
		map = BASE_PROVIDER_MAP,
		http = BASE_PROVIDER_HTTP,
		stream = BASE_PROVIDER_STREAM,
	};

	enum class stream_provider : std::uint32_t
	{
		flat = STREAM_PROVIDER_FLAT,
		partial = STREAM_PROVIDER_PARTIAL,
		mpqe = STREAM_PROVIDER_MPQE,
		block4 = STREAM_PROVIDER_BLOCK4,
	};

	enum class stream_flag : std::uint32_t
	{
		none = 0,
		read_only = STREAM_FLAG_READ_ONLY,
		write_share = STREAM_FLAG_WRITE_SHARE,
		use_bitmap = STREAM_FLAG_USE_BITMAP,
	};

	STORMLIB_PP_FLAGS(stream_flag);

	enum class mpq_open_flag : std::uint32_t
	{
		none = 0,
		no_listfile = MPQ_OPEN_NO_LISTFILE,
		no_attributes = MPQ_OPEN_NO_ATTRIBUTES,
		no_header_search = MPQ_OPEN_NO_HEADER_SEARCH,
		force_mpq_v1 = MPQ_OPEN_FORCE_MPQ_V1,
		check_sector_crc = MPQ_OPEN_CHECK_SECTOR_CRC,
	};

	STORMLIB_PP_FLAGS(mpq_open_flag);

	enum class mpq_create_flag : std::uint32_t
	{
		none = 0,
		create_listfile = MPQ_CREATE_LISTFILE,
		create_attributes = MPQ_CREATE_ATTRIBUTES,
		create_signature = MPQ_CREATE_SIGNATURE,
		version_1 = MPQ_CREATE_ARCHIVE_V1,
		version_2 = MPQ_CREATE_ARCHIVE_V2,
		version_3 = MPQ_CREATE_ARCHIVE_V3,
		version_4 = MPQ_CREATE_ARCHIVE_V4,
		version_mask = MPQ_CREATE_ARCHIVE_VMASK,
	};

	STORMLIB_PP_FLAGS(mpq_create_flag);

	enum class verify_file_flag : std::uint32_t
	{
		none = 0,
		sector_crc = SFILE_VERIFY_SECTOR_CRC,
		file_crc = SFILE_VERIFY_FILE_CRC,
		file_md5 = SFILE_VERIFY_FILE_MD5,
		raw_md5 = SFILE_VERIFY_RAW_MD5,
		all = SFILE_VERIFY_ALL,
	};

	STORMLIB_PP_FLAGS(verify_file_flag);

	enum class signature_type : std::uint32_t
	{
		none = SIGNATURE_TYPE_NONE,
		weak = SIGNATURE_TYPE_WEAK,
		strong = SIGNATURE_TYPE_STRONG,
	};

	enum class archive_info : std::uint32_t
	{
		file_name,
		user_data_offset,
		user_data,
		header_offset,
		header_size,
		het_table_offset,
		het_table_size,
		bet_table_offset,
		bet_table_size,
		hash_table_offset,
		hash_table_size_64,
		hash_table_size,
		block_table_offset,
		block_table_size_64,
		block_table_size,
		hiblock_table_offset,
		hiblock_table_size_64,
		signatures,
		strong_signature_offset,
		strong_signature_size,
		strong_signature,
		archive_size_64,
		archive_size,
		max_file_count,
		file_table_size,
		sector_size,
		number_of_files,
		raw_chunk_size,
		stream_flags,
		base_provider,
		mpq_flags,
	};

	enum class file_info : std::uint32_t
	{
		patch_chain,
		hash_index,
		name_hash_1,
		name_hash_2,
		name_hash_3,
		locale,
		file_index,
		byte_offset,
		file_time,
		file_size,
		compressed_size,
		flags,
		encryption_key,
		encryption_key_raw,
	};

	enum class seek_method : std::uint32_t
	{
		begin = FILE_BEGIN,
		current = FILE_CURRENT,
		end = FILE_END,
	};

	enum class verify_file_result_flag : std::uint32_t
	{
		none = 0,
		open_error = VERIFY_OPEN_ERROR,
		read_error = VERIFY_READ_ERROR,
		has_sector_crc = VERIFY_FILE_HAS_SECTOR_CRC,
		sector_crc_error = VERIFY_FILE_SECTOR_CRC_ERROR,
		has_checksum = VERIFY_FILE_HAS_CHECKSUM,
		checksum_error = VERIFY_FILE_CHECKSUM_ERROR,
		has_md5 = VERIFY_FILE_HAS_MD5,
		md5_error = VERIFY_FILE_MD5_ERROR,
		has_raw_md5 = VERIFY_FILE_HAS_RAW_MD5,
		raw_md5_error = VERIFY_FILE_RAW_MD5_ERROR,
		error_mask = VERIFY_FILE_ERROR_MASK,
	};

	STORMLIB_PP_FLAGS(verify_file_result_flag);

	enum class verify_archive_result : std::uint32_t
	{
		no_signature = ERROR_NO_SIGNATURE,
		verify_failed = ERROR_VERIFY_FAILED,
		weak_signature_ok = ERROR_WEAK_SIGNATURE_OK,
		weak_signature_error = ERROR_WEAK_SIGNATURE_ERROR,
		strong_signature_ok = ERROR_STRONG_SIGNATURE_OK,
		strong_signature_error = ERROR_STRONG_SIGNATURE_ERROR,
	};

	namespace internal
	{
		template<typename TObj>
		void get_file_info_data(const TObj& obj, SFileInfoClass infoClass, void* item, std::uint32_t size)
		{
			obj.get_file_info_data(infoClass, item, size);
		}

		template<typename TObj>
		void get_file_info_size(const TObj& obj, SFileInfoClass infoClass, std::uint32_t& size)
		{
			obj.get_file_info_size(infoClass, size);
		}

		template<typename TObj, typename TData>
		void get_file_info_data(const TObj& obj, SFileInfoClass infoClass, TData* item, std::uint32_t count)
		{
			static_assert(std::is_trivial<TData>::value, "TData must be trivial");
			get_file_info_data(obj, infoClass, reinterpret_cast<void*>(item), count * sizeof(TData));
		}

		template<SFileInfoClass C, typename T>
		struct get_info_single
		{
			typedef T type;

			template<typename UObj>
			static type get(const UObj& obj)
			{
				type ret;
				get_file_info_data(obj, C, &ret, 1);
				return ret;
			}
		};

		template<SFileInfoClass C, typename T>
		struct get_info_string
		{
			typedef std::basic_string<T> type;

			template<typename UObj>
			static type get(const UObj& obj)
			{
				std::uint32_t size;
				get_file_info_size(obj, C, size);
				size /= sizeof(T);
				type ret;
				ret.resize(size);
				get_file_info_data(obj, C, const_cast<T*>(ret.data()), size);
				return ret;
			}
		};

		template<SFileInfoClass C, typename T>
		struct get_info_vector
		{
			typedef std::vector<T> type;

			template<typename UObj>
			static type get(const UObj& obj)
			{
				std::uint32_t size;
				get_file_info_size(obj, C, size);
				size /= sizeof(T);
				type ret;
				ret.resize(size);
				get_file_info_data(obj, C, ret.data(), size);
				return ret;
			}
		};

		template<SFileInfoClass C, typename TEnum, std::uint32_t Mask>
		struct get_info_enum
		{
			typedef TEnum type;

			template<typename UObj>
			static type get(const UObj& obj)
			{
				return static_cast<type>(get_info_single<C, std::uint32_t>::get(obj) & Mask);
			}
		};

		template<archive_info>
		struct get_archive_info;

		template<> struct get_archive_info<archive_info::file_name> : public get_info_string<SFileMpqFileName, TCHAR> {};
		template<> struct get_archive_info<archive_info::user_data_offset> : public get_info_single<SFileMpqUserDataOffset, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::user_data> : public get_info_vector<SFileMpqUserData, std::uint8_t> {};
		template<> struct get_archive_info<archive_info::header_offset> : public get_info_single<SFileMpqHeaderOffset, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::header_size> : public get_info_single<SFileMpqHeaderSize, std::uint32_t> {};
		template<> struct get_archive_info<archive_info::het_table_offset> : public get_info_single<SFileMpqHetTableOffset, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::het_table_size> : public get_info_single<SFileMpqHetTableSize, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::bet_table_offset> : public get_info_single<SFileMpqBetTableOffset, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::bet_table_size> : public get_info_single<SFileMpqBetTableSize, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::hash_table_offset> : public get_info_single<SFileMpqHashTableOffset, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::hash_table_size_64> : public get_info_single<SFileMpqHashTableSize64, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::hash_table_size> : public get_info_single<SFileMpqHashTableSize, std::uint32_t> {};
		template<> struct get_archive_info<archive_info::block_table_offset> : public get_info_single<SFileMpqBlockTableOffset, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::block_table_size_64> : public get_info_single<SFileMpqBlockTableSize64, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::block_table_size> : public get_info_single<SFileMpqBlockTableSize, std::uint32_t> {};
		template<> struct get_archive_info<archive_info::hiblock_table_offset> : public get_info_single<SFileMpqHiBlockTableOffset, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::hiblock_table_size_64> : public get_info_single<SFileMpqHiBlockTableSize64, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::signatures> : public get_info_enum<SFileMpqSignatures, signature_type, 0x03> {};
		template<> struct get_archive_info<archive_info::strong_signature_offset> : public get_info_single<SFileMpqStrongSignatureOffset, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::strong_signature_size> : public get_info_single<SFileMpqStrongSignatureSize, std::uint32_t> {};
		template<> struct get_archive_info<archive_info::strong_signature> : public get_info_vector<SFileMpqStrongSignature, std::uint8_t> {};
		template<> struct get_archive_info<archive_info::archive_size_64> : public get_info_single<SFileMpqArchiveSize64, std::uint64_t> {};
		template<> struct get_archive_info<archive_info::archive_size> : public get_info_single<SFileMpqArchiveSize, std::uint32_t> {};
		template<> struct get_archive_info<archive_info::max_file_count> : public get_info_single<SFileMpqMaxFileCount, std::uint32_t> {};
		template<> struct get_archive_info<archive_info::file_table_size> : public get_info_single<SFileMpqFileTableSize, std::uint32_t> {};
		template<> struct get_archive_info<archive_info::sector_size> : public get_info_single<SFileMpqSectorSize, std::uint32_t> {};
		template<> struct get_archive_info<archive_info::number_of_files> : public get_info_single<SFileMpqNumberOfFiles, std::uint32_t> {};
		template<> struct get_archive_info<archive_info::raw_chunk_size> : public get_info_single<SFileMpqRawChunkSize, std::uint32_t> {};
		template<> struct get_archive_info<archive_info::stream_flags> : public get_info_enum<SFileMpqStreamFlags, stream_flag, 0xFF00> {};
		template<> struct get_archive_info<archive_info::base_provider> : public get_info_enum<SFileMpqStreamFlags, base_provider, 0x000F> {};
		template<> struct get_archive_info<archive_info::mpq_flags> : public get_info_enum<SFileMpqFlags, mpq_flag, 0xFFFF> {};

		template<file_info>
		struct get_file_info;

		template<> struct get_file_info<file_info::patch_chain> : public get_info_string<SFileInfoPatchChain, TCHAR> {};
		template<> struct get_file_info<file_info::hash_index> : public get_info_single<SFileInfoHashIndex, std::uint32_t> {};
		template<> struct get_file_info<file_info::name_hash_1> : public get_info_single<SFileInfoNameHash1, std::uint32_t> {};
		template<> struct get_file_info<file_info::name_hash_2> : public get_info_single<SFileInfoNameHash2, std::uint32_t> {};
		template<> struct get_file_info<file_info::name_hash_3> : public get_info_single<SFileInfoNameHash3, std::uint64_t> {};
		template<> struct get_file_info<file_info::locale> : public get_info_single<SFileInfoLocale, LCID> {};
		template<> struct get_file_info<file_info::file_index> : public get_info_single<SFileInfoFileIndex, std::uint32_t> {};
		template<> struct get_file_info<file_info::byte_offset> : public get_info_single<SFileInfoByteOffset, std::uint64_t> {};
		template<> struct get_file_info<file_info::file_time> : public get_info_single<SFileInfoFileTime, std::uint64_t> {};
		template<> struct get_file_info<file_info::file_size> : public get_info_single<SFileInfoFileSize, std::uint32_t> {};
		template<> struct get_file_info<file_info::compressed_size> : public get_info_single<SFileInfoCompressedSize, std::uint32_t> {};
		template<> struct get_file_info<file_info::flags> : public get_info_enum<SFileInfoFlags, file_flag, 0xFFFFFFFF> {};
		template<> struct get_file_info<file_info::encryption_key> : public get_info_single<SFileInfoEncryptionKey, std::uint32_t> {};
		template<> struct get_file_info<file_info::encryption_key_raw> : public get_info_single<SFileInfoEncryptionKeyRaw, std::uint32_t> {};
	}

	typedef std::function<void(std::uint32_t bytesWritten, std::uint32_t totalBytes, bool finalCall)> add_file_callback;

	struct compact_callback final
	{
		std::function<void(std::uint64_t current, std::uint64_t total)> checking_files_callback;
		std::function<void(std::uint64_t current, std::uint64_t total)> checking_hash_table_callback;
		std::function<void(std::uint64_t current, std::uint64_t total)> copying_non_mpq_data_callback;
		std::function<void(std::uint64_t current, std::uint64_t total)> compacting_archive_callback;
		std::function<void(std::uint64_t current, std::uint64_t total)> closing_archive_callback;
	};

	struct create_mpq final
	{
		mpq_format_version version;
		base_provider base_provider;
		stream_provider stream_provider;
		stream_flag stream_flags;
		file_flag listfile_flags;
		file_flag attributes_flags;
		file_flag signature_flags;
		attribute_flag file_attributes;
		std::uint32_t sector_size;
		std::uint32_t raw_chunk_size;
		std::uint32_t max_file_count;

		create_mpq();
		create_mpq(const create_mpq&) = default;
		create_mpq(create_mpq&&) = default;
		create_mpq& operator=(const create_mpq&) = default;
		create_mpq& operator=(create_mpq&&) = default;
		~create_mpq() = default;
	};

	class istream_provider
	{
	protected:
		istream_provider() = default;
		~istream_provider() = default;

	public:
		istream_provider(const istream_provider&) = delete;
		istream_provider(istream_provider&&) = delete;
		istream_provider& operator=(const istream_provider&) = delete;
		istream_provider& operator=(istream_provider&&) = delete;

		virtual std::uint32_t read(std::uint64_t offset, void* buffer, std::uint32_t toRead) = 0;
		virtual std::uint32_t write(std::uint64_t offset, const void* buffer, std::uint32_t toWrite) = 0;
		virtual void resize(std::uint64_t newSize) = 0;
	};

	class istream_provider_factory
	{
	protected:
		istream_provider_factory() = default;

	public:
		istream_provider_factory(const istream_provider_factory&) = delete;
		istream_provider_factory(istream_provider_factory&&) = delete;
		istream_provider_factory& operator=(const istream_provider_factory&) = delete;
		istream_provider_factory& operator=(istream_provider_factory&&) = delete;
		virtual ~istream_provider_factory() = default;

		virtual void create(t_cstr fileName, bool shareWrite, std::shared_ptr<istream_provider>& stream) = 0;
		virtual void open(t_cstr fileName, bool readOnly, bool shareWrite, std::shared_ptr<istream_provider>& stream, std::uint64_t& fileSize, std::uint64_t& fileTime) = 0;
		virtual void close(const std::shared_ptr<istream_provider>& stream) = 0;
	};

	LCID get_locale();
	LCID set_locale(LCID newLocale);

	class archive final
	{
	public:
		struct data;

		const data* get() const;
		data* get();

	private:
		std::shared_ptr<data> m_data;

		void initialize(const std::shared_ptr<istream_provider_factory>& factory);

	public:
		archive(const std::shared_ptr<istream_provider_factory>& factory, t_cstr mpqName, base_provider baseProvider, stream_provider streamProvider, stream_flag streamFlags, mpq_open_flag flags);
		archive(const std::shared_ptr<istream_provider_factory>& factory, t_cstr mpqName, mpq_create_flag flags, std::uint32_t maxFileCount);
		archive(const std::shared_ptr<istream_provider_factory>& factory, t_cstr mpqName, const create_mpq& data);
		archive(const std::shared_ptr<istream_provider_factory>& factory, const tstring& mpqName, base_provider baseProvider, stream_provider streamProvider, stream_flag streamFlags, mpq_open_flag flags);
		archive(const std::shared_ptr<istream_provider_factory>& factory, const tstring& mpqName, mpq_create_flag flags, std::uint32_t maxFileCount);
		archive(const std::shared_ptr<istream_provider_factory>& factory, const tstring& mpqName, const create_mpq& data);
		archive(const stormlib::archive& other);
		archive(archive&& other);
		archive& operator=(const stormlib::archive& other);
		archive& operator=(archive&& other);
		~archive();

		HANDLE handle() const;

		void set_compact_callback(compact_callback&& callback);
		void set_compact_callback(const compact_callback& callback);
		const compact_callback& get_compact_callback() const;

		void set_add_file_callback(add_file_callback&& callback);
		void set_add_file_callback(const add_file_callback& callback);
		const add_file_callback& get_add_file_callback() const;

		void flush();

		void add_list_file(a_cstr listFile);
		void add_list_file(const astring& listFile);

		void compact_archive(a_cstr listFile);
		void compact_archive(const astring& listFile);

		std::uint32_t get_max_file_count() const;
		void set_max_file_count(std::uint32_t value) const;

		attribute_flag get_attributes() const;
		void set_attributes(attribute_flag value);
		void update_file_attributes(a_cstr fileName);
		void update_file_attributes(const astring& fileName);

		void open_patch_archive(t_cstr patchMpqName, a_cstr patchPrefix);
		void open_patch_archive(const tstring& patchMpqName, const astring& patchPrefix);
		bool is_patched() const;

		bool has_file(a_cstr fileName) const;
		bool has_file(const astring& fileName) const;

		template<archive_info Info>
		auto get_info() const
		{
			return internal::get_archive_info<Info>::get(*this);
		}

		void get_file_info_data(SFileInfoClass infoClass, void* item, std::uint32_t size) const;
		void get_file_info_size(SFileInfoClass infoClass, std::uint32_t& size) const;

		void extract_file(a_cstr toExtract, t_cstr extracted);
		void extract_file(const astring& toExtract, const tstring& extracted);

		verify_file_result_flag verify_file(a_cstr fileName, verify_file_flag flags) const;
		verify_file_result_flag verify_file(const astring& fileName, verify_file_flag flags) const;

		void sign();

		verify_archive_result verify() const;

		std::vector<LCID> enum_locales(a_cstr fileName) const;
		std::vector<LCID> enum_locales(const astring& fileName) const;

		void add_file(t_cstr fileName, a_cstr archivedName, add_file_flag flags, compression_flag compression, compression_flag next);
		void add_file(t_cstr fileName, a_cstr archivedName, add_file_flag flags, compression_flag compression);
		void add_file(const tstring& fileName, const astring& archivedName, add_file_flag flags, compression_flag compression, compression_flag next);
		void add_file(const tstring& fileName, const astring& archivedName, add_file_flag flags, compression_flag compression);

		void remove_file(a_cstr fileName);
		void remove_file(const astring& fileName);
		void rename_file(a_cstr oldFileName, a_cstr newFileName);
		void rename_file(const astring& oldFileName, const astring& newFileName);
	};

	class archive_read_file final
	{
	private:
		struct data;

		std::shared_ptr<data> m_data;

	public:
		archive_read_file(const stormlib::archive& archive, a_cstr fileName);
		archive_read_file(const stormlib::archive& archive, const astring& fileName);
		archive_read_file(const archive_read_file& other);
		archive_read_file(archive_read_file&& other);
		archive_read_file& operator=(const archive_read_file& other);
		archive_read_file& operator=(archive_read_file&& other);
		~archive_read_file();

		const stormlib::archive& archive() const;
		stormlib::archive& archive();
		HANDLE handle() const;

		std::uint64_t file_size() const;
		std::uint64_t file_pointer();
		std::uint64_t file_pointer(std::uint64_t value);
		LCID locale() const;
		void locale(LCID locale);

		std::uint64_t seek(std::int64_t value, seek_method method);

		std::uint32_t read(void* buffer, std::uint32_t toRead);

		astring file_name() const;

		void get_file_info_data(SFileInfoClass infoClass, void* item, std::uint32_t size) const;
		void get_file_info_size(SFileInfoClass infoClass, std::uint32_t& size) const;

		template<file_info Info>
		auto get_info() const
		{
			return internal::get_file_info<Info>::get(*this);
		}
	};

	class archive_write_file final
	{
	private:
		struct data;

		std::shared_ptr<data> m_data;

	public:
		archive_write_file(const stormlib::archive& archive, a_cstr fileName, std::uint64_t fileTime, std::uint32_t fileSize, LCID locale, add_file_flag flags);
		archive_write_file(const stormlib::archive& archive, const astring& fileName, std::uint64_t fileTime, std::uint32_t fileSize, LCID locale, add_file_flag flags);
		archive_write_file(const archive_write_file& other);
		archive_write_file(archive_write_file&& other);
		archive_write_file& operator=(const archive_write_file& other);
		archive_write_file& operator=(archive_write_file&& other);
		~archive_write_file();

		const stormlib::archive& archive() const;
		stormlib::archive& archive();
		HANDLE handle() const;
		std::uint32_t file_size() const;
		std::uint32_t file_pointer() const;
		LCID locale() const;
		const astring& file_name() const;

		void write(const void* data, std::uint32_t size, compression_flag compression);
		void finish();
	};

	class archive_enumerator final
	{
	private:
		struct data;

		std::shared_ptr<data> m_data;

	public:
		archive_enumerator(const stormlib::archive& archive, a_cstr mask, a_cstr listFile);
		archive_enumerator(const stormlib::archive& archive, a_cstr listFile);
		archive_enumerator(const stormlib::archive& archive, const astring& mask, const astring& listFile);
		archive_enumerator(const stormlib::archive& archive, const astring& listFile);
		archive_enumerator(const stormlib::archive& archive);
		archive_enumerator(const archive_enumerator& other);
		archive_enumerator(archive_enumerator&& other);
		archive_enumerator& operator=(const archive_enumerator& other);
		archive_enumerator& operator=(archive_enumerator&& other);
		~archive_enumerator();

		const stormlib::archive& archive() const;
		stormlib::archive& archive();
		HANDLE handle() const;
		bool is_valid() const;
		a_cstr file_name() const;
		a_cstr plain_name() const;
		std::uint32_t hash_index() const;
		std::uint32_t block_index() const;
		std::uint32_t file_size() const;
		file_flag file_flags() const;
		std::uint32_t compressed_size() const;
		std::uint64_t file_time() const;
		LCID locale() const;

		void next();
	};

	class listfile_enumerator final
	{
	private:
		struct data;

		std::shared_ptr<data> m_data;

	public:
		listfile_enumerator(const stormlib::archive& archive, a_cstr mask, a_cstr listFile);
		listfile_enumerator(const stormlib::archive& archive, a_cstr listFile);
		listfile_enumerator(const stormlib::archive& archive, const astring& mask, const astring& listFile);
		listfile_enumerator(const stormlib::archive& archive, const astring& listFile);
		listfile_enumerator(const stormlib::archive& archive);
		listfile_enumerator(const listfile_enumerator& other);
		listfile_enumerator(listfile_enumerator&& other);
		listfile_enumerator& operator=(const listfile_enumerator& other);
		listfile_enumerator& operator=(listfile_enumerator&& other);
		~listfile_enumerator();

		const stormlib::archive& archive() const;
		stormlib::archive& archive();
		HANDLE handle() const;
		bool is_valid() const;
		a_cstr file_name() const;
		a_cstr plain_name() const;
		std::uint32_t hash_index() const;
		std::uint32_t block_index() const;
		std::uint32_t file_size() const;
		file_flag file_flags() const;
		std::uint32_t compressed_size() const;
		std::uint64_t file_time() const;
		LCID locale() const;

		void next();
	};

	class stormlib_exception : public std::exception
	{
	protected:
		stormlib_exception() = default;

	public:
		stormlib_exception(const stormlib_exception&) = default;
		stormlib_exception(stormlib_exception&&) = default;
		stormlib_exception& operator=(const stormlib_exception&) = default;
		stormlib_exception& operator=(stormlib_exception&&) = default;
		virtual ~stormlib_exception() = default;

		virtual std::uint32_t code() const = 0;
	};

	class io_exception : public stormlib_exception
	{
	protected:
		io_exception() = default;

	public:
		io_exception(const io_exception&) = default;
		io_exception(io_exception&&) = default;
		io_exception& operator=(const io_exception&) = default;
		io_exception& operator=(io_exception&&) = default;
		virtual ~io_exception() = default;
	};

	class file_not_found_exception : public io_exception
	{
	public:
		file_not_found_exception() = default;
		file_not_found_exception(const file_not_found_exception&) = default;
		file_not_found_exception(file_not_found_exception&&) = default;
		file_not_found_exception& operator=(const file_not_found_exception&) = default;
		file_not_found_exception& operator=(file_not_found_exception&&) = default;
		virtual ~file_not_found_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class access_denied_exception : public stormlib_exception
	{
	public:
		access_denied_exception() = default;
		access_denied_exception(const access_denied_exception&) = default;
		access_denied_exception(access_denied_exception&&) = default;
		access_denied_exception& operator=(const access_denied_exception&) = default;
		access_denied_exception& operator=(access_denied_exception&&) = default;
		virtual ~access_denied_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class invalid_handle_exception : public stormlib_exception
	{
	public:
		invalid_handle_exception() = default;
		invalid_handle_exception(const invalid_handle_exception&) = default;
		invalid_handle_exception(invalid_handle_exception&&) = default;
		invalid_handle_exception& operator=(const invalid_handle_exception&) = default;
		invalid_handle_exception& operator=(invalid_handle_exception&&) = default;
		virtual ~invalid_handle_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class not_supported_exception : public stormlib_exception
	{
	public:
		not_supported_exception() = default;
		not_supported_exception(const not_supported_exception&) = default;
		not_supported_exception(not_supported_exception&&) = default;
		not_supported_exception& operator=(const not_supported_exception&) = default;
		not_supported_exception& operator=(not_supported_exception&&) = default;
		virtual ~not_supported_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class disk_full_exception : public io_exception
	{
	public:
		disk_full_exception() = default;
		disk_full_exception(const disk_full_exception&) = default;
		disk_full_exception(disk_full_exception&&) = default;
		disk_full_exception& operator=(const disk_full_exception&) = default;
		disk_full_exception& operator=(disk_full_exception&&) = default;
		virtual ~disk_full_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class already_exists_exception : public io_exception
	{
	public:
		already_exists_exception() = default;
		already_exists_exception(const already_exists_exception&) = default;
		already_exists_exception(already_exists_exception&&) = default;
		already_exists_exception& operator=(const already_exists_exception&) = default;
		already_exists_exception& operator=(already_exists_exception&&) = default;
		virtual ~already_exists_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class insufficient_buffer_exception : public stormlib_exception
	{
	public:
		insufficient_buffer_exception() = default;
		insufficient_buffer_exception(const insufficient_buffer_exception&) = default;
		insufficient_buffer_exception(insufficient_buffer_exception&&) = default;
		insufficient_buffer_exception& operator=(const insufficient_buffer_exception&) = default;
		insufficient_buffer_exception& operator=(insufficient_buffer_exception&&) = default;
		virtual ~insufficient_buffer_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class bad_format_exception : public stormlib_exception
	{
	public:
		bad_format_exception() = default;
		bad_format_exception(const bad_format_exception&) = default;
		bad_format_exception(bad_format_exception&&) = default;
		bad_format_exception& operator=(const bad_format_exception&) = default;
		bad_format_exception& operator=(bad_format_exception&&) = default;
		virtual ~bad_format_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class no_more_files_exception : public io_exception
	{
	public:
		no_more_files_exception() = default;
		no_more_files_exception(const no_more_files_exception&) = default;
		no_more_files_exception(no_more_files_exception&&) = default;
		no_more_files_exception& operator=(const no_more_files_exception&) = default;
		no_more_files_exception& operator=(no_more_files_exception&&) = default;
		virtual ~no_more_files_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class handle_eof_exception : public io_exception
	{
	public:
		handle_eof_exception() = default;
		handle_eof_exception(const handle_eof_exception&) = default;
		handle_eof_exception(handle_eof_exception&&) = default;
		handle_eof_exception& operator=(const handle_eof_exception&) = default;
		handle_eof_exception& operator=(handle_eof_exception&&) = default;
		virtual ~handle_eof_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class can_not_complete_exception : public stormlib_exception
	{
	public:
		can_not_complete_exception() = default;
		can_not_complete_exception(const can_not_complete_exception&) = default;
		can_not_complete_exception(can_not_complete_exception&&) = default;
		can_not_complete_exception& operator=(const can_not_complete_exception&) = default;
		can_not_complete_exception& operator=(can_not_complete_exception&&) = default;
		virtual ~can_not_complete_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class file_corrupt_exception : public io_exception
	{
	public:
		file_corrupt_exception() = default;
		file_corrupt_exception(const file_corrupt_exception&) = default;
		file_corrupt_exception(file_corrupt_exception&&) = default;
		file_corrupt_exception& operator=(const file_corrupt_exception&) = default;
		file_corrupt_exception& operator=(file_corrupt_exception&&) = default;
		virtual ~file_corrupt_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class avi_file_exception : public io_exception
	{
	public:
		avi_file_exception() = default;
		avi_file_exception(const avi_file_exception&) = default;
		avi_file_exception(avi_file_exception&&) = default;
		avi_file_exception& operator=(const avi_file_exception&) = default;
		avi_file_exception& operator=(avi_file_exception&&) = default;
		virtual ~avi_file_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class unknown_file_key_exception : public io_exception
	{
	public:
		unknown_file_key_exception() = default;
		unknown_file_key_exception(const unknown_file_key_exception&) = default;
		unknown_file_key_exception(unknown_file_key_exception&&) = default;
		unknown_file_key_exception& operator=(const unknown_file_key_exception&) = default;
		unknown_file_key_exception& operator=(unknown_file_key_exception&&) = default;
		virtual ~unknown_file_key_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class checksum_error_exception : public io_exception
	{
	public:
		checksum_error_exception() = default;
		checksum_error_exception(const checksum_error_exception&) = default;
		checksum_error_exception(checksum_error_exception&&) = default;
		checksum_error_exception& operator=(const checksum_error_exception&) = default;
		checksum_error_exception& operator=(checksum_error_exception&&) = default;
		virtual ~checksum_error_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class internal_file_exception : public io_exception
	{
	public:
		internal_file_exception() = default;
		internal_file_exception(const internal_file_exception&) = default;
		internal_file_exception(internal_file_exception&&) = default;
		internal_file_exception& operator=(const internal_file_exception&) = default;
		internal_file_exception& operator=(internal_file_exception&&) = default;
		virtual ~internal_file_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class base_file_missing_exception : public io_exception
	{
	public:
		base_file_missing_exception() = default;
		base_file_missing_exception(const base_file_missing_exception&) = default;
		base_file_missing_exception(base_file_missing_exception&&) = default;
		base_file_missing_exception& operator=(const base_file_missing_exception&) = default;
		base_file_missing_exception& operator=(base_file_missing_exception&&) = default;
		virtual ~base_file_missing_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class marked_for_delete_exception : public io_exception
	{
	public:
		marked_for_delete_exception() = default;
		marked_for_delete_exception(const marked_for_delete_exception&) = default;
		marked_for_delete_exception(marked_for_delete_exception&&) = default;
		marked_for_delete_exception& operator=(const marked_for_delete_exception&) = default;
		marked_for_delete_exception& operator=(marked_for_delete_exception&&) = default;
		virtual ~marked_for_delete_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class file_incomplete_exception : public io_exception
	{
	public:
		file_incomplete_exception() = default;
		file_incomplete_exception(const file_incomplete_exception&) = default;
		file_incomplete_exception(file_incomplete_exception&&) = default;
		file_incomplete_exception& operator=(const file_incomplete_exception&) = default;
		file_incomplete_exception& operator=(file_incomplete_exception&&) = default;
		virtual ~file_incomplete_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class unknown_file_names_exception : public io_exception
	{
	public:
		unknown_file_names_exception() = default;
		unknown_file_names_exception(const unknown_file_names_exception&) = default;
		unknown_file_names_exception(unknown_file_names_exception&&) = default;
		unknown_file_names_exception& operator=(const unknown_file_names_exception&) = default;
		unknown_file_names_exception& operator=(unknown_file_names_exception&&) = default;
		virtual ~unknown_file_names_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class cant_find_patch_prefix_exception : public io_exception
	{
	public:
		cant_find_patch_prefix_exception() = default;
		cant_find_patch_prefix_exception(const cant_find_patch_prefix_exception&) = default;
		cant_find_patch_prefix_exception(cant_find_patch_prefix_exception&&) = default;
		cant_find_patch_prefix_exception& operator=(const cant_find_patch_prefix_exception&) = default;
		cant_find_patch_prefix_exception& operator=(cant_find_patch_prefix_exception&&) = default;
		virtual ~cant_find_patch_prefix_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class unknown_exception : public stormlib_exception
	{
	private:
		std::uint32_t m_code;

	public:
		explicit unknown_exception(std::uint32_t code);
		unknown_exception(const unknown_exception&) = default;
		unknown_exception(unknown_exception&&) = default;
		unknown_exception& operator=(const unknown_exception&) = default;
		unknown_exception& operator=(unknown_exception&&) = default;
		virtual ~unknown_exception() = default;

		a_cstr what() const override;
		std::uint32_t code() const override;
	};

	class aggregate_exception : public std::exception
	{
	private:
		std::vector<std::exception_ptr> m_subExceptions;
		bool m_exceptionsLost;

	public:
		aggregate_exception(std::vector<std::exception_ptr>&& subExceptions, bool exceptionsLost);
		aggregate_exception(const aggregate_exception&) = default;
		aggregate_exception(aggregate_exception&&) = default;
		aggregate_exception& operator=(const aggregate_exception&) = default;
		aggregate_exception& operator=(aggregate_exception&&) = default;
		virtual ~aggregate_exception() = default;

		a_cstr what() const override;
		const std::vector<std::exception_ptr>& sub_exceptions() const;
		bool exceptions_lost() const;
	};
}

#undef STORMLIB_PP_FLAGS