#include <cassert>
#include <stdexcept>
#include <utility>
#include "stormlib++.hpp"

#define STORMLIB_PP_NORETURN					__declspec(noreturn) void

#define STORMLIB_PP_ARCHIVE_FUNC_EX(ptr)		local_exception_context lec(&(ptr)->get()->context)
#define STORMLIB_PP_ARCHIVE_FUNC()				STORMLIB_PP_ARCHIVE_FUNC_EX(this)
#define STORMLIB_PP_READ_FILE_FUNC_EX(ptr)		local_exception_context lec(((ptr)->m_data->archive.get()) ? &(ptr)->m_data->archive.get()->context : nullptr)
#define STORMLIB_PP_READ_FILE_FUNC()			STORMLIB_PP_READ_FILE_FUNC_EX(this)
#define STORMLIB_PP_WRITE_FILE_FUNC_EX(ptr)		local_exception_context lec(&(ptr)->m_data->archive.get()->context)
#define STORMLIB_PP_WRITE_FILE_FUNC()			STORMLIB_PP_WRITE_FILE_FUNC_EX(this)
#define STORMLIB_PP_ARCHIVE_ENUM_FUNC_EX(ptr)	local_exception_context lec(&(ptr)->m_data->archive.get()->context)
#define STORMLIB_PP_ARCHIVE_ENUM_FUNC()			STORMLIB_PP_ARCHIVE_ENUM_FUNC_EX(this)
#define STORMLIB_PP_LISTFILE_ENUM_FUNC_EX(ptr)	local_exception_context lec(&(ptr)->m_data->archive.get()->context)
#define STORMLIB_PP_LISTFILE_ENUM_FUNC()		STORMLIB_PP_LISTFILE_ENUM_FUNC_EX(this)

#define STORMLIB_PP_CHECK_CALL(func, call, ...)		lec.check_call<error_filter<__VA_ARGS__>>([&]() { return (call); })
#define STORMLIB_PP_CHECK_CALL_EX(func, call, ...)	lec.check_ex_call<error_filter<__VA_ARGS__>>([&]() { return (call); })
#define STORMLIB_PP_THROW_LENGTH_MISMATCH()			lec.throw_length_mismatch()

#define STORMLIB_PP_EXCEPTION_SWALLOWED	0x1000F

#define STORMLIB_PP_MAKE_CTOR_DTOR(type)																\
	type::type() : m_data(nullptr) {}																	\
	type::type(const type& other) : m_data(other.m_data) { if(this->m_data) this->m_data->add_ref(); }	\
	type::type(type&& other) : m_data(other.m_data) { other.m_data = nullptr; }							\
	type& type::operator=(const type& other) {															\
		if (this != &other) {																			\
			if(this->m_data) this->m_data->release();													\
			this->m_data = other.m_data;																\
			if(this->m_data) this->m_data->add_ref(); }													\
		return *this; }																					\
	type& type::operator=(type&& other) {																\
		if (this != &other) std::swap(this->m_data, other.m_data);										\
		return *this; }																					\
	type::~type() {																						\
		if(this->m_data) this->m_data->release();														\
		this->m_data = nullptr; }

namespace stormlib
{
	namespace
	{
		struct exception_context final
		{
		private:
			std::vector<std::exception_ptr> m_exceptions;
			bool m_exceptionsLost;

		public:
			exception_context() :
				m_exceptionsLost(false)
			{
			}

			exception_context(const exception_context&) = delete;
			exception_context(exception_context&&) = delete;
			exception_context& operator=(const exception_context&) = delete;
			exception_context& operator=(exception_context&&) = delete;
			~exception_context() = default;

			DWORD add(std::exception_ptr&& ptr)
			{
				DWORD ret = STORMLIB_PP_EXCEPTION_SWALLOWED;
				if (ptr) {
					try {
						try {
							std::rethrow_exception(ptr);
						}
						catch (const std::bad_alloc&) {
							ret = ERROR_NOT_ENOUGH_MEMORY;
						}
						catch (const std::invalid_argument&) {
							ret = ERROR_INVALID_PARAMETER;
						}
						catch (const stormlib_exception& ex) {
							ret = ex.code();
						}
						catch (...) {
							//swallow
						}
						this->m_exceptions.push_back(std::forward<std::exception_ptr>(ptr));
					}
					catch (...) {
						//swallow silently
						this->m_exceptionsLost = true;
					}
				}
				return ret;
			}

			void check()
			{
				if (this->m_exceptions.empty() && !this->m_exceptionsLost) return;
				throw aggregate_exception(std::move(this->m_exceptions), this->m_exceptionsLost);
			}

			template<typename T>
			STORMLIB_PP_NORETURN try_throw(T&& ex)
			{
				if (this->m_exceptions.empty() && !this->m_exceptionsLost) throw ex;
				try {
					try {
						throw ex;
					}
					catch (...) {
						this->m_exceptions.push_back(std::current_exception());
					}
				}
				catch (...) {
					//swallow silently
					this->m_exceptionsLost = true;
				}
				throw aggregate_exception(std::move(this->m_exceptions), this->m_exceptionsLost);
			}
		};

		template<DWORD... Err>
		struct error_filter;

		template<DWORD Curr, DWORD... Rem>
		struct error_filter<Curr, Rem...>
		{
			static bool is_failure(DWORD error)
			{
				return error != Curr && error_filter<Rem...>::is_failure(error);
			}
		};

		template<>
		struct error_filter<>
		{
			static bool is_failure(DWORD error)
			{
				return error != ERROR_SUCCESS;
			}
		};

		struct local_exception_context final
		{
		private:
			exception_context* m_context;

			template<typename T>
			STORMLIB_PP_NORETURN try_throw(T&& ex)
			{
				if (this->m_context) this->m_context->try_throw(std::forward<T>(ex));
				throw ex;
			}

			void handle_error(DWORD error)
			{
				switch (error) {
				case ERROR_SUCCESS: return; //not an error
				case ERROR_FILE_NOT_FOUND: this->try_throw(file_not_found_exception());
				case ERROR_ACCESS_DENIED: this->try_throw(access_denied_exception());
				case ERROR_INVALID_HANDLE: this->try_throw(invalid_handle_exception());
				case ERROR_NOT_ENOUGH_MEMORY: this->try_throw(std::bad_alloc());
				case ERROR_NOT_SUPPORTED: this->try_throw(not_supported_exception());
				case ERROR_INVALID_PARAMETER: this->try_throw(std::invalid_argument(u8"invalid argument value"));
				case ERROR_DISK_FULL: this->try_throw(disk_full_exception());
				case ERROR_ALREADY_EXISTS: this->try_throw(already_exists_exception());
				case ERROR_INSUFFICIENT_BUFFER: this->try_throw(insufficient_buffer_exception());
				case ERROR_BAD_FORMAT: this->try_throw(bad_format_exception());
				case ERROR_NO_MORE_FILES: this->try_throw(no_more_files_exception());
				case ERROR_HANDLE_EOF: this->try_throw(handle_eof_exception());
				case ERROR_CAN_NOT_COMPLETE: this->try_throw(can_not_complete_exception());
				case ERROR_FILE_CORRUPT: this->try_throw(file_corrupt_exception());
				case ERROR_AVI_FILE: this->try_throw(avi_file_exception());
				case ERROR_UNKNOWN_FILE_KEY: this->try_throw(unknown_file_key_exception());
				case ERROR_CHECKSUM_ERROR: this->try_throw(checksum_error_exception());
				case ERROR_INTERNAL_FILE: this->try_throw(internal_file_exception());
				case ERROR_BASE_FILE_MISSING: this->try_throw(base_file_missing_exception());
				case ERROR_MARKED_FOR_DELETE: this->try_throw(marked_for_delete_exception());
				case ERROR_FILE_INCOMPLETE: this->try_throw(file_incomplete_exception());
				case ERROR_UNKNOWN_FILE_NAMES: this->try_throw(unknown_file_names_exception());
				case ERROR_CANT_FIND_PATCH_PREFIX: this->try_throw(cant_find_patch_prefix_exception());
				case STORMLIB_PP_EXCEPTION_SWALLOWED:
					if (this->m_context) this->m_context->check();
					break;
				default:
					this->try_throw(unknown_exception(error));
				}
			}

		public:
			local_exception_context(exception_context* ctx) :
				m_context(ctx)
			{
			}

			local_exception_context(const local_exception_context&) = delete;
			local_exception_context(local_exception_context&&) = delete;
			local_exception_context& operator=(const local_exception_context&) = delete;
			local_exception_context& operator=(local_exception_context&&) = delete;
			~local_exception_context() = default;

			template<typename TFilter, typename TCall>
			DWORD check_call(TCall&& call)
			{
				SetLastError(ERROR_SUCCESS);
				auto val = call();
				static_assert(std::is_same<decltype(val), bool>::value, "result must be a bool");
				DWORD error = GetLastError();
				if (!val && TFilter::is_failure(error)) handle_error(error);
				if (this->m_context) this->m_context->check();
				return error;
			}

			template<typename TFilter, typename TCall>
			DWORD check_ex_call(TCall&& call)
			{
				auto val = call();
				static_assert(std::is_same<decltype(val), int>::value, "result must be a DWORD");
				if (TFilter::is_failure(val)) handle_error(val);
				if (this->m_context) this->m_context->check();
				return val;
			}

			STORMLIB_PP_NORETURN throw_length_mismatch()
			{
				this->try_throw(insufficient_buffer_exception());
			}
		};

		struct compact_callback_wrapper final
		{
		private:
			exception_context* m_ctx;
			HANDLE m_handle;
			compact_callback* m_callback;

			static void WINAPI func(void * pvUserData, DWORD dwWorkType, ULONGLONG BytesProcessed, ULONGLONG TotalBytes)
			{
				if (pvUserData) {
					compact_callback_wrapper* me = reinterpret_cast<compact_callback_wrapper*>(pvUserData);
					try {
						switch (dwWorkType) {
						case CCB_CHECKING_FILES:
							if (me->m_callback->checking_files_callback) me->m_callback->checking_files_callback(BytesProcessed, TotalBytes);
							break;
						case CCB_CHECKING_HASH_TABLE:
							if (me->m_callback->checking_hash_table_callback) me->m_callback->checking_hash_table_callback(BytesProcessed, TotalBytes);
							break;
						case CCB_CLOSING_ARCHIVE:
							if (me->m_callback->closing_archive_callback) me->m_callback->closing_archive_callback(BytesProcessed, TotalBytes);
							break;
						case CCB_COMPACTING_FILES:
							if (me->m_callback->compacting_archive_callback) me->m_callback->compacting_archive_callback(BytesProcessed, TotalBytes);
							break;
						case CCB_COPYING_NON_MPQ_DATA:
							if (me->m_callback->copying_non_mpq_data_callback) me->m_callback->copying_non_mpq_data_callback(BytesProcessed, TotalBytes);
							break;
						}
					}
					catch (...) {
						me->m_ctx->add(std::current_exception());
					}
				}
			}

		public:
			compact_callback_wrapper(exception_context& ctx, HANDLE handle, compact_callback& callback) :
				m_ctx(&ctx),
				m_handle(handle),
				m_callback(&callback)
			{
				if (!this->m_callback->checking_files_callback
					&& !this->m_callback->checking_hash_table_callback
					&& !this->m_callback->closing_archive_callback
					&& !this->m_callback->compacting_archive_callback
					&& !this->m_callback->copying_non_mpq_data_callback)
				{
					this->m_handle = NULL;
				}
				if (this->m_handle) SFileSetCompactCallback(this->m_handle, &func, this);
			}

			compact_callback_wrapper(const compact_callback_wrapper&) = delete;
			compact_callback_wrapper(compact_callback_wrapper&&) = delete;
			compact_callback_wrapper& operator=(const compact_callback_wrapper&) = delete;
			compact_callback_wrapper& operator=(compact_callback_wrapper&&) = delete;

			~compact_callback_wrapper()
			{
				if (this->m_handle) SFileSetCompactCallback(this->m_handle, &func, this);
				this->m_handle = NULL;
			}

			void done()
			{
				this->m_ctx->check();
			}
		};

		struct add_file_callback_wrapper final
		{
		private:
			exception_context* m_ctx;
			HANDLE m_handle;
			add_file_callback* m_callback;

			static void WINAPI func(void * pvUserData, DWORD dwBytesWritten, DWORD dwTotalBytes, bool bFinalCall)
			{
				if (pvUserData) {
					add_file_callback_wrapper* me = reinterpret_cast<add_file_callback_wrapper*>(pvUserData);
					try {
						if (me->m_callback->operator bool()) me->m_callback->operator()(dwBytesWritten, dwTotalBytes, bFinalCall);
					}
					catch (...) {
						me->m_ctx->add(std::current_exception());
					}
				}
			}

		public:
			add_file_callback_wrapper(exception_context& ctx, HANDLE handle, add_file_callback& callback) :
				m_ctx(&ctx),
				m_handle(handle),
				m_callback(&callback)
			{
				if (!this->m_callback->operator bool()) this->m_handle = NULL;
				if (this->m_handle != NULL) SFileSetAddFileCallback(this->m_handle, &func, this);
			}

			add_file_callback_wrapper(const add_file_callback_wrapper&) = delete;
			add_file_callback_wrapper(add_file_callback_wrapper&&) = delete;
			add_file_callback_wrapper& operator=(const add_file_callback_wrapper&) = delete;
			add_file_callback_wrapper& operator=(add_file_callback_wrapper&&) = delete;

			~add_file_callback_wrapper()
			{
				if (this->m_handle != NULL) SFileSetAddFileCallback(this->m_handle, &func, this);
				this->m_handle = NULL;
			}

			void done()
			{
				this->m_ctx->check();
			}
		};

		struct stream_provider_wrapper final
		{
		private:
			std::shared_ptr<istream_provider> m_provider;
			TStreamProvider m_impl;
			exception_context* m_ctx;

			static bool WINAPI read(void * pData, ULONGLONG ByteOffset, void * pvBuffer, DWORD dwBytesToRead, DWORD* pBytesRead)
			{
				if (!pData || !pvBuffer || !pBytesRead) {
					SetLastError(ERROR_INVALID_PARAMETER);
					return false;
				}
				stream_provider_wrapper* me = reinterpret_cast<stream_provider_wrapper*>(pData);
				try {
					*pBytesRead = me->m_provider->read(ByteOffset, pvBuffer, dwBytesToRead);
					return true;
				}
				catch (...) {
					SetLastError(me->m_ctx->add(std::current_exception()));
					return false;
				}
			}

			static bool WINAPI write(void * pData, ULONGLONG ByteOffset, const void * pvBuffer, DWORD dwBytesToWrite, DWORD* pBytesWritten)
			{
				if (!pData || !pvBuffer || !pBytesWritten) {
					SetLastError(ERROR_INVALID_PARAMETER);
					return false;
				}
				stream_provider_wrapper* me = reinterpret_cast<stream_provider_wrapper*>(pData);
				try {
					*pBytesWritten = me->m_provider->write(ByteOffset, pvBuffer, dwBytesToWrite);
					return true;
				}
				catch (...) {
					SetLastError(me->m_ctx->add(std::current_exception()));
					return false;
				}
			}

			static bool WINAPI resize(void * pData, ULONGLONG NewSize)
			{
				if (!pData) {
					SetLastError(ERROR_INVALID_PARAMETER);
					return false;
				}
				stream_provider_wrapper* me = reinterpret_cast<stream_provider_wrapper*>(pData);
				try {
					me->m_provider->resize(NewSize);
					return true;
				}
				catch (...) {
					SetLastError(me->m_ctx->add(std::current_exception()));
					return false;
				}
			}

		public:
			stream_provider_wrapper() :
				m_ctx(0)
			{
				memset(&this->m_impl, 0, sizeof(this->m_impl));
			}

			stream_provider_wrapper(const stream_provider_wrapper&) = delete;
			stream_provider_wrapper(stream_provider_wrapper&&) = delete;
			stream_provider_wrapper& operator=(const stream_provider_wrapper&) = delete;
			stream_provider_wrapper& operator=(stream_provider_wrapper&&) = delete;
			~stream_provider_wrapper() = default;

			void initialize(exception_context& ctx, const std::shared_ptr<istream_provider>& provider)
			{
				this->m_ctx = &ctx;
				this->m_provider = provider;
				this->m_impl.pData = this;
				this->m_impl.Read = &read;
				this->m_impl.Resize = &resize;
				this->m_impl.Write = &write;
			}

			TStreamProvider* get()
			{
				return &this->m_impl;
			}
		};

		struct stream_provider_factory_wrapper final
		{
		private:
			std::shared_ptr<istream_provider_factory> m_factory;
			TStreamProviderFactory m_impl;
			exception_context* m_ctx;

			bool wrap_provider(const std::shared_ptr<istream_provider>& provider, TStreamProvider*& pProvider)
			{
				if (!provider) {
					SetLastError(ERROR_INVALID_HANDLE);
					return false;
				}
				std::unique_ptr<stream_provider_wrapper> ret = std::make_unique<stream_provider_wrapper>();
				ret->initialize(*this->m_ctx, provider);
				pProvider = ret->get();
				ret.release();
				return true;
			}

			static bool WINAPI create_stream(void * pData, const TCHAR * szFileName, bool ShareWrite, TStreamProvider ** ppProvider)
			{
				if (!pData || !szFileName || !ppProvider) {
					SetLastError(ERROR_INVALID_PARAMETER);
					return false;
				}
				stream_provider_factory_wrapper* me = reinterpret_cast<stream_provider_factory_wrapper*>(pData);
				try {
					std::shared_ptr<istream_provider> provider;
					me->m_factory->create(szFileName, ShareWrite, provider);
					return me->wrap_provider(provider, *ppProvider);
				}
				catch (...) {
					SetLastError(me->m_ctx->add(std::current_exception()));
					return false;
				}
			}

			static bool WINAPI open_stream(void * pData, const TCHAR * szFileName, bool ReadOnly, bool ShareWrite, TStreamProvider ** ppProvider, ULONGLONG* pFileSize, ULONGLONG* pFileTime)
			{
				if (!pData || !szFileName || !ppProvider || !pFileSize || !pFileTime) {
					SetLastError(ERROR_INVALID_PARAMETER);
					return false;
				}
				stream_provider_factory_wrapper* me = reinterpret_cast<stream_provider_factory_wrapper*>(pData);
				try {
					std::shared_ptr<istream_provider> provider;
					me->m_factory->open(szFileName, ReadOnly, ShareWrite, provider, *pFileSize, *pFileTime);
					return me->wrap_provider(provider, *ppProvider);
				}
				catch (...) {
					SetLastError(me->m_ctx->add(std::current_exception()));
					return false;
				}
			}

			static bool WINAPI close_stream(void * pData, TStreamProvider * pProvider)
			{
				if (!pData || !pProvider) {
					SetLastError(ERROR_INVALID_PARAMETER);
					return false;
				}
				delete reinterpret_cast<stream_provider_wrapper*>(pProvider->pData);
				return true;
			}

		public:
			stream_provider_factory_wrapper() :
				m_ctx(NULL)
			{
				memset(&this->m_impl, 0, sizeof(this->m_impl));
			}

			stream_provider_factory_wrapper(const stream_provider_factory_wrapper&) = delete;
			stream_provider_factory_wrapper(stream_provider_factory_wrapper&&) = delete;
			stream_provider_factory_wrapper& operator=(const stream_provider_factory_wrapper&) = delete;
			stream_provider_factory_wrapper& operator=(stream_provider_factory_wrapper&&) = delete;
			~stream_provider_factory_wrapper() = default;

			void initialize(exception_context& ctx, std::shared_ptr<istream_provider_factory> factory)
			{
				this->m_ctx = &ctx;
				this->m_factory = factory;
				this->m_impl.pData = this;
				this->m_impl.Create = &create_stream;
				this->m_impl.Open = &open_stream;
				this->m_impl.Close = &close_stream;
			}

			TStreamProviderFactory* get()
			{
				return this->m_factory ? &this->m_impl : nullptr;
			}
		};

		struct base_data
		{
		private:
			std::int32_t m_refCnt;

		protected:
			~base_data()
			{
				assert(this->m_refCnt == 0);
			}

		public:
			base_data() :
				m_refCnt(1)
			{
			}

			base_data(const base_data&) = delete;
			base_data(base_data&&) = delete;
			base_data& operator=(const base_data&) = delete;
			base_data& operator=(base_data&&) = delete;

			void add_ref()
			{
				++this->m_refCnt;
			}

			void release()
			{
				assert(this->m_refCnt > 0);
				--this->m_refCnt;
				if (this->m_refCnt == 0) delete this;
			}
		};
	}

	create_mpq::create_mpq() :
		version(mpq_format_version::_1),
		base_provider(base_provider::file),
		stream_provider(stream_provider::flat),
		stream_flags(stream_flag::none),
		listfile_flags(file_flag::none),
		attributes_flags(file_flag::none),
		signature_flags(file_flag::none),
		file_attributes(attribute_flag::none),
		sector_size(4096),
		raw_chunk_size(4096),
		max_file_count(hash_table_size_default)
	{
	}

	LCID get_locale()
	{
		return SFileGetLocale();
	}

	LCID set_locale(LCID newLocale)
	{
		return SFileSetLocale(newLocale);
	}

	struct archive::data final : public base_data
	{
		compact_callback compact_callback;
		add_file_callback add_file_callback;
		stream_provider_factory_wrapper factory;
		mutable exception_context context;
		HANDLE handle;

		data() :
			handle(NULL)
		{
		}

		data(const data&) = delete;
		data(data&&) = delete;
		data& operator=(const data&) = delete;
		data& operator=(data&&) = delete;

	private:
		~data()
		{
			if (this->handle != NULL) SFileCloseArchive(this->handle);
			this->handle = NULL;
		}
	};

	const archive::data* archive::get() const
	{
		return this->m_data;
	}

	archive::data* archive::get()
	{
		return this->m_data;
	}

	void archive::initialize(const std::shared_ptr<istream_provider_factory>& factory)
	{
		this->get()->factory.initialize(this->get()->context, factory);
	}

	STORMLIB_PP_MAKE_CTOR_DTOR(archive);

	archive archive::open(const std::shared_ptr<istream_provider_factory>& factory, t_cstr mpqName, base_provider baseProvider, stream_provider streamProvider, stream_flag stream)
	{
		archive ret;
		ret.m_data = new archive::data();
		STORMLIB_PP_ARCHIVE_FUNC_EX(&ret);
		ret.initialize(factory);
		STORMLIB_PP_CHECK_CALL(SFileOpenArchive, SFileOpenArchive(ret.get()->factory.get(), mpqName, 0, static_cast<DWORD>(baseProvider) | static_cast<DWORD>(streamProvider) | static_cast<DWORD>(stream), &ret.get()->handle) != false);
		return ret;
	}

	archive archive::create(const std::shared_ptr<istream_provider_factory>& factory, t_cstr mpqName, mpq_create_flag flags, std::uint32_t maxFileCount)
	{
		archive ret;
		ret.m_data = new archive::data();
		STORMLIB_PP_ARCHIVE_FUNC_EX(&ret);
		ret.initialize(factory);
		STORMLIB_PP_CHECK_CALL(SFileCreateArchive, SFileCreateArchive(ret.get()->factory.get(), mpqName, static_cast<DWORD>(flags), maxFileCount, &ret.get()->handle) != false);
		return ret;
	}

	archive archive::create(const std::shared_ptr<istream_provider_factory>& factory, t_cstr mpqName, const create_mpq& data)
	{
		archive ret;
		ret.m_data = new archive::data();
		STORMLIB_PP_ARCHIVE_FUNC_EX(&ret);
		ret.initialize(factory);
		SFILE_CREATE_MPQ d;
		memset(&d, 0, sizeof(d));
		d.cbSize = sizeof(d);
		d.dwAttrFlags = static_cast<DWORD>(data.file_attributes);
		d.dwFileFlags1 = static_cast<DWORD>(data.listfile_flags);
		d.dwFileFlags2 = static_cast<DWORD>(data.attributes_flags);
		d.dwFileFlags3 = static_cast<DWORD>(data.signature_flags);
		d.dwMaxFileCount = data.max_file_count;
		d.dwMpqVersion = static_cast<DWORD>(data.version);
		d.dwRawChunkSize = data.raw_chunk_size;
		d.dwSectorSize = data.sector_size;
		d.dwStreamFlags = static_cast<DWORD>(data.base_provider) | static_cast<DWORD>(data.stream_provider) | static_cast<DWORD>(data.stream_flags);
		STORMLIB_PP_CHECK_CALL(SFileCreateArchive2, SFileCreateArchive2(ret.get()->factory.get(), mpqName, &d, &ret.get()->handle) != false);
		return ret;
	}

	archive archive::open(const std::shared_ptr<istream_provider_factory>& factory, const tstring& mpqName, base_provider baseProvider, stream_provider streamProvider, stream_flag stream)
	{
		return open(factory, mpqName.c_str(), baseProvider, streamProvider, stream);
	}

	archive archive::create(const std::shared_ptr<istream_provider_factory>& factory, const tstring& mpqName, mpq_create_flag flags, std::uint32_t maxFileCount)
	{
		return create(factory, mpqName.c_str(), flags, maxFileCount);
	}

	archive archive::create(const std::shared_ptr<istream_provider_factory>& factory, const tstring& mpqName, const create_mpq& data)
	{
		return create(factory, mpqName.c_str(), data);
	}

	HANDLE archive::handle() const
	{
		return this->get()->handle;
	}

	void archive::set_compact_callback(compact_callback&& callback)
	{
		this->get()->compact_callback = std::forward<compact_callback>(callback);
	}

	void archive::set_compact_callback(const compact_callback& callback)
	{
		this->get()->compact_callback = callback;
	}

	const compact_callback& archive::get_compact_callback() const
	{
		return this->get()->compact_callback;
	}

	void archive::set_add_file_callback(add_file_callback&& callback)
	{
		this->get()->add_file_callback = std::forward<add_file_callback>(callback);
	}

	void archive::set_add_file_callback(const add_file_callback& callback)
	{
		this->get()->add_file_callback = callback;
	}

	const add_file_callback& archive::get_add_file_callback() const
	{
		return this->get()->add_file_callback;
	}

	void archive::flush()
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		STORMLIB_PP_CHECK_CALL(SFileFlushArchive, SFileFlushArchive(this->handle()) != false);
	}

	void archive::add_list_file(a_cstr listFile)
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		STORMLIB_PP_CHECK_CALL_EX(SFileAddListFile, SFileAddListFile(this->handle(), listFile));
	}

	void archive::add_list_file(const astring& listFile)
	{
		this->add_list_file(listFile.c_str());
	}

	void archive::compact_archive(a_cstr listFile)
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		compact_callback_wrapper callback(this->get()->context, this->handle(), this->get()->compact_callback);
		STORMLIB_PP_CHECK_CALL(SFileCompactArchive, SFileCompactArchive(this->handle(), listFile, false) != false);
		callback.done();
	}

	void archive::compact_archive(const astring& listFile)
	{
		this->compact_archive(listFile.c_str());
	}

	std::uint32_t archive::get_max_file_count() const
	{
		return this->get_info<archive_info::max_file_count>();
	}

	void archive::set_max_file_count(std::uint32_t value) const
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		STORMLIB_PP_CHECK_CALL(SFileSetMaxFileCount, SFileSetMaxFileCount(this->handle(), value) != false);
	}

	attribute_flag archive::get_attributes() const
	{
		return static_cast<attribute_flag>(SFileGetAttributes(this->handle()));
	}

	void archive::set_attributes(attribute_flag value)
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		STORMLIB_PP_CHECK_CALL(SFileSetAttributes, SFileSetAttributes(this->handle(), static_cast<DWORD>(value)) != false);
	}

	void archive::update_file_attributes(a_cstr fileName)
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		STORMLIB_PP_CHECK_CALL(SFileUpdateFileAttributes, SFileUpdateFileAttributes(this->handle(), fileName) != false);
	}

	void archive::update_file_attributes(const astring& fileName)
	{
		this->update_file_attributes(fileName.c_str());
	}

	void archive::open_patch_archive(t_cstr patchMpqName, a_cstr patchPrefix)
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		STORMLIB_PP_CHECK_CALL(SFileOpenPatchArchive, SFileOpenPatchArchive(this->handle(), patchMpqName, patchPrefix, 0) != false);
	}

	void archive::open_patch_archive(const tstring& patchMpqName, const astring& patchPrefix)
	{
		this->open_patch_archive(patchMpqName.c_str(), patchPrefix.c_str());
	}

	bool archive::is_patched() const
	{
		return SFileIsPatchedArchive(this->handle());
	}

	bool archive::has_file(a_cstr fileName) const
	{
		return SFileHasFile(this->handle(), fileName);
	}

	bool archive::has_file(const astring& fileName) const
	{
		return this->has_file(fileName.c_str());
	}

	void archive::get_file_info_data(SFileInfoClass infoClass, void* item, std::uint32_t size) const
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		DWORD len;
		STORMLIB_PP_CHECK_CALL(SFileGetFileInfo, SFileGetFileInfo(this->handle(), infoClass, item, size, &len) != false);
		if (len != size) STORMLIB_PP_THROW_LENGTH_MISMATCH();
	}

	void archive::get_file_info_size(SFileInfoClass infoClass, std::uint32_t& size) const
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		DWORD len;
		STORMLIB_PP_CHECK_CALL(SFileGetFileInfo, SFileGetFileInfo(this->handle(), infoClass, nullptr, 0, &len) != false);
		size = static_cast<std::uint32_t>(len);
	}

	void archive::extract_file(a_cstr toExtract, t_cstr extracted)
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		STORMLIB_PP_CHECK_CALL(SFileExtractFile, SFileExtractFile(this->handle(), toExtract, extracted, SFILE_OPEN_FROM_MPQ) != false);
	}

	void archive::extract_file(const astring& toExtract, const tstring& extracted)
	{
		this->extract_file(toExtract.c_str(), extracted.c_str());
	}

	verify_file_result_flag archive::verify_file(a_cstr fileName, verify_file_flag flags) const
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		DWORD ret;
		STORMLIB_PP_CHECK_CALL(SFileVerifyFile, ((ret = SFileVerifyFile(this->handle(), fileName, static_cast<DWORD>(flags))) & VERIFY_OPEN_ERROR) == 0);
		return static_cast<verify_file_result_flag>(ret);
	}

	verify_file_result_flag archive::verify_file(const astring& fileName, verify_file_flag flags) const
	{
		return this->verify_file(fileName.c_str(), flags);
	}

	void archive::sign()
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		STORMLIB_PP_CHECK_CALL(SFileSignArchive, SFileSignArchive(this->handle(), SIGNATURE_TYPE_WEAK) != false);
	}

	verify_archive_result archive::verify() const
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		DWORD ret;
		STORMLIB_PP_CHECK_CALL(SFileVerifyArchive, ((ret = SFileVerifyArchive(this->handle())) & ERROR_VERIFY_FAILED) == 0);
		return static_cast<verify_archive_result>(ret);
	}

	std::vector<LCID> archive::enum_locales(a_cstr fileName) const
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		DWORD maxCnt = 0;
		STORMLIB_PP_CHECK_CALL_EX(SFileEnumLocales, SFileEnumLocales(this->handle(), fileName, NULL, &maxCnt, 0));
		std::vector<LCID> ret;
		if (maxCnt > 0) {
			ret.resize(maxCnt);
			STORMLIB_PP_CHECK_CALL_EX(SFileEnumLocales, SFileEnumLocales(this->handle(), fileName, ret.data(), &maxCnt, 0));
		}
		return ret;
	}

	std::vector<LCID> archive::enum_locales(const astring& fileName) const
	{
		return this->enum_locales(fileName.c_str());
	}

	void archive::add_file(t_cstr fileName, a_cstr archivedName, add_file_flag flags, compression_flag compression, compression_flag next)
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		add_file_callback_wrapper callback(this->get()->context, this->handle(), this->get()->add_file_callback);
		STORMLIB_PP_CHECK_CALL(SFileAddFileEx, SFileAddFileEx(this->handle(), fileName, archivedName, static_cast<DWORD>(flags), static_cast<DWORD>(compression), static_cast<DWORD>(next)) != false);
		callback.done();
	}

	void archive::add_file(t_cstr fileName, a_cstr archivedName, add_file_flag flags, compression_flag compression)
	{
		this->add_file(fileName, archivedName, flags, compression, compression);
	}

	void archive::add_file(const tstring& fileName, const astring& archivedName, add_file_flag flags, compression_flag compression, compression_flag next)
	{
		this->add_file(fileName.c_str(), archivedName.c_str(), flags, compression, next);
	}

	void archive::add_file(const tstring& fileName, const astring& archivedName, add_file_flag flags, compression_flag compression)
	{
		this->add_file(fileName.c_str(), archivedName.c_str(), flags, compression);
	}

	void archive::remove_file(a_cstr fileName)
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		STORMLIB_PP_CHECK_CALL(SFileRemoveFile, SFileRemoveFile(this->handle(), fileName, 0) != false);
	}

	void archive::remove_file(const astring& fileName)
	{
		this->remove_file(fileName.c_str());
	}

	void archive::rename_file(a_cstr oldFileName, a_cstr newFileName)
	{
		STORMLIB_PP_ARCHIVE_FUNC();
		STORMLIB_PP_CHECK_CALL(SFileRenameFile, SFileRenameFile(this->handle(), oldFileName, newFileName) != false);
	}

	void archive::rename_file(const astring& oldFileName, const astring& newFileName)
	{
		this->rename_file(oldFileName.c_str(), newFileName.c_str());
	}

	struct archive_read_file::data final : public base_data
	{
	public:
		archive archive;
		HANDLE handle;

		data() :
			handle(NULL)
		{
		}

		data(const data&) = delete;
		data(data&&) = delete;
		data& operator=(const data&) = delete;
		data& operator=(data&&) = delete;

	private:
		~data()
		{
			if (this->handle) SFileCloseFile(this->handle);
			this->handle = NULL;
		}
	};

	STORMLIB_PP_MAKE_CTOR_DTOR(archive_read_file);

	archive_read_file archive_read_file::open(const archive& archive, a_cstr fileName)
	{
		archive_read_file ret;
		ret.m_data = new archive_read_file::data();
		ret.m_data->archive = archive;
		STORMLIB_PP_READ_FILE_FUNC_EX(&ret);
		STORMLIB_PP_CHECK_CALL(SFileOpenFileEx, SFileOpenFileEx(ret.m_data->archive.handle(), fileName, SFILE_OPEN_FROM_MPQ, &ret.m_data->handle) != false);
		return ret;
	}

	archive_read_file archive_read_file::open_local(a_cstr fileName)
	{
		archive_read_file ret;
		ret.m_data = new archive_read_file::data();
		STORMLIB_PP_READ_FILE_FUNC_EX(&ret);
		STORMLIB_PP_CHECK_CALL(SFileOpenFileEx, SFileOpenFileEx(NULL, fileName, SFILE_OPEN_LOCAL_FILE, &ret.m_data->handle) != false);
		return ret;
	}

	archive_read_file archive_read_file::open(const archive& archive, const astring& fileName)
	{
		return open(archive, fileName.c_str());
	}

	archive_read_file archive_read_file::open_local(const astring& fileName)
	{
		return open_local(fileName.c_str());
	}

	HANDLE archive_read_file::handle() const
	{
		return this->m_data->handle;
	}

	std::uint64_t archive_read_file::file_size() const
	{
		STORMLIB_PP_READ_FILE_FUNC();
		ULARGE_INTEGER ul;
		STORMLIB_PP_CHECK_CALL(SFileGetFileSize, (ul.LowPart = SFileGetFileSize(this->handle(), &ul.HighPart)) != SFILE_INVALID_SIZE);
		return ul.QuadPart;
	}

	std::uint64_t archive_read_file::file_pointer()
	{
		return this->seek(0, seek_method::current);
	}

	std::uint64_t archive_read_file::file_pointer(std::uint64_t value)
	{
		return this->seek(static_cast<std::int64_t>(value), seek_method::begin);
	}

	LCID archive_read_file::locale() const
	{
		return this->get_info<file_info::locale>();
	}

	void archive_read_file::locale(LCID locale)
	{
		STORMLIB_PP_READ_FILE_FUNC();
		STORMLIB_PP_CHECK_CALL(SFileSetFileLocale, SFileSetFileLocale(this->handle(), locale) != false);
	}

	std::uint64_t archive_read_file::seek(std::int64_t value, seek_method method)
	{
		STORMLIB_PP_READ_FILE_FUNC();
		LARGE_INTEGER li;
		li.QuadPart = value;
		STORMLIB_PP_CHECK_CALL(SFileSetFilePointer, (li.LowPart = SFileSetFilePointer(this->handle(), li.LowPart, &li.HighPart, static_cast<DWORD>(method))) != SFILE_INVALID_POS);
		return static_cast<std::uint64_t>(li.QuadPart);
	}

	std::uint32_t archive_read_file::read(void* buffer, std::uint32_t toRead)
	{
		STORMLIB_PP_READ_FILE_FUNC();
		DWORD read;
		STORMLIB_PP_CHECK_CALL(SFileReadFile, SFileReadFile(this->handle(), buffer, toRead, &read, nullptr) != false, ERROR_HANDLE_EOF);
		return read;
	}

	astring archive_read_file::file_name() const
	{
		STORMLIB_PP_READ_FILE_FUNC();
		char buffer[MAX_PATH + 1];
		STORMLIB_PP_CHECK_CALL(SFileGetFileName, SFileGetFileName(this->handle(), buffer) != false);
		return astring(buffer);
	}

	void archive_read_file::get_file_info_data(SFileInfoClass infoClass, void* item, std::uint32_t size) const
	{
		STORMLIB_PP_READ_FILE_FUNC();
		DWORD len;
		STORMLIB_PP_CHECK_CALL(SFileGetFileInfo, SFileGetFileInfo(this->handle(), infoClass, item, size, &len) != false);
		if (len != size) STORMLIB_PP_THROW_LENGTH_MISMATCH();
	}

	void archive_read_file::get_file_info_size(SFileInfoClass infoClass, std::uint32_t& size) const
	{
		STORMLIB_PP_READ_FILE_FUNC();
		DWORD len;
		STORMLIB_PP_CHECK_CALL(SFileGetFileInfo, SFileGetFileInfo(this->handle(), infoClass, nullptr, 0, &len) != false);
		size = static_cast<std::uint32_t>(len);
	}

	struct archive_write_file::data final : public base_data
	{
	public:
		archive archive;
		HANDLE handle;
		astring file_name;
		std::uint32_t file_size;
		std::uint32_t file_pointer;
		LCID locale;

		data() :
			handle(NULL),
			file_size(0),
			file_pointer(0),
			locale(language_neutral)
		{
		}

		data(const data&) = delete;
		data(data&&) = delete;
		data& operator=(const data&) = delete;
		data& operator=(data&&) = delete;

	private:
		~data()
		{
			if (this->handle != NULL) SFileFinishFile(this->handle);
			this->handle = NULL;
		}
	};

	STORMLIB_PP_MAKE_CTOR_DTOR(archive_write_file);

	archive_write_file archive_write_file::create(const archive& archive, a_cstr fileName, std::uint64_t fileTime, std::uint32_t fileSize, LCID locale, add_file_flag flags)
	{
		archive_write_file ret;
		ret.m_data = new archive_write_file::data();
		ret.m_data->archive = archive;
		STORMLIB_PP_WRITE_FILE_FUNC_EX(&ret);
		STORMLIB_PP_CHECK_CALL(SFileCreateFile, SFileCreateFile(ret.m_data->archive.handle(), fileName, fileTime, fileSize, locale, static_cast<DWORD>(flags), &ret.m_data->handle) != false);
		ret.m_data->file_name = fileName;
		ret.m_data->file_size = fileSize;
		ret.m_data->file_pointer = 0;
		ret.m_data->locale = locale;
		return ret;
	}

	archive_write_file archive_write_file::create(const archive& archive, const astring& fileName, std::uint64_t fileTime, std::uint32_t fileSize, LCID locale, add_file_flag flags)
	{
		return create(archive, fileName.c_str(), fileTime, fileSize, locale, flags);
	}

	HANDLE archive_write_file::handle() const
	{
		return this->m_data->handle;
	}

	std::uint32_t archive_write_file::file_size() const
	{
		return this->m_data->file_size;
	}

	std::uint32_t archive_write_file::file_pointer() const
	{
		return this->m_data->file_pointer;
	}

	LCID archive_write_file::locale() const
	{
		return this->m_data->locale;
	}

	const astring& archive_write_file::file_name() const
	{
		return this->m_data->file_name;
	}

	void archive_write_file::write(const void* data, std::uint32_t size, compression_flag compression)
	{
		STORMLIB_PP_WRITE_FILE_FUNC();
		STORMLIB_PP_CHECK_CALL(SFileWriteFile, SFileWriteFile(this->handle(), data, size, static_cast<DWORD>(compression)) != false);
		this->m_data->file_pointer += size;
	}

	void archive_write_file::finish()
	{
		STORMLIB_PP_WRITE_FILE_FUNC();
		STORMLIB_PP_CHECK_CALL(SFileFinishFile, SFileFinishFile(this->handle()) != false);
		this->m_data->handle = NULL;
	}

	struct archive_enumerator::data final : public base_data
	{
	public:
		archive archive;
		HANDLE handle;
		SFILE_FIND_DATA find_data;

		data() :
			handle(NULL)
		{
			memset(&this->find_data, 0, sizeof(this->find_data));
		}

		data(const data&) = delete;
		data(data&&) = delete;
		data& operator=(const data&) = delete;
		data& operator=(data&&) = delete;

	private:
		~data()
		{
			if (this->handle != NULL) SFileFindClose(this->handle);
			this->handle;
		}
	};

	STORMLIB_PP_MAKE_CTOR_DTOR(archive_enumerator);

	archive_enumerator archive_enumerator::create(const archive& archive, a_cstr mask, a_cstr listFile)
	{
		archive_enumerator ret;
		ret.m_data = new archive_enumerator::data();
		ret.m_data->archive = archive;
		STORMLIB_PP_ARCHIVE_ENUM_FUNC_EX(&ret);
		if (STORMLIB_PP_CHECK_CALL(SFileFindFirstFile, (ret.m_data->handle = SFileFindFirstFile(ret.m_data->archive.handle(), mask, &ret.m_data->find_data, listFile)) != NULL, ERROR_NO_MORE_FILES) == ERROR_NO_MORE_FILES) {
			ret.m_data->handle = NULL;
		}
		return ret;
	}

	archive_enumerator archive_enumerator::create(const archive& archive, a_cstr listFile)
	{
		return create(archive, "*", listFile);
	}

	archive_enumerator archive_enumerator::create(const archive& archive, const astring& mask, const astring& listFile)
	{
		return create(archive, mask.c_str(), listFile.c_str());
	}

	archive_enumerator archive_enumerator::create(const archive& archive, const astring& listFile)
	{
		return create(archive, listFile.c_str());
	}

	archive_enumerator archive_enumerator::create(const archive& archive)
	{
		return create(archive, nullptr);
	}

	HANDLE archive_enumerator::handle() const
	{
		return this->m_data->handle;
	}

	bool archive_enumerator::is_valid() const
	{
		return this->handle() != NULL;
	}

	a_cstr archive_enumerator::file_name() const
	{
		if (!this->is_valid()) return nullptr;
		return this->m_data->find_data.cFileName;
	}

	a_cstr archive_enumerator::plain_name() const
	{
		if (!this->is_valid()) return nullptr;
		return this->m_data->find_data.szPlainName;
	}

	std::uint32_t archive_enumerator::hash_index() const
	{
		if (!this->is_valid()) return 0;
		return this->m_data->find_data.dwHashIndex;
	}

	std::uint32_t archive_enumerator::block_index() const
	{
		if (!this->is_valid()) return 0;
		return this->m_data->find_data.dwBlockIndex;
	}

	std::uint32_t archive_enumerator::file_size() const
	{
		if (!this->is_valid()) return 0;
		return this->m_data->find_data.dwFileSize;
	}

	file_flag archive_enumerator::file_flags() const
	{
		if (!this->is_valid()) return file_flag::none;
		return static_cast<file_flag>(this->m_data->find_data.dwFileFlags);
	}

	std::uint32_t archive_enumerator::compressed_size() const
	{
		if (!this->is_valid()) return 0;
		return this->m_data->find_data.dwCompSize;
	}

	std::uint64_t archive_enumerator::file_time() const
	{
		if (!this->is_valid()) return 0;
		ULARGE_INTEGER ul;
		ul.LowPart = this->m_data->find_data.dwFileTimeLo;
		ul.HighPart = this->m_data->find_data.dwFileTimeHi;
		return ul.QuadPart;
	}

	LCID archive_enumerator::locale() const
	{
		if (!this->is_valid()) return language_neutral;
		return this->m_data->find_data.lcLocale;
	}

	bool archive_enumerator::next()
	{
		if (!this->is_valid()) return false;
		STORMLIB_PP_ARCHIVE_ENUM_FUNC();
		if (STORMLIB_PP_CHECK_CALL(SFileFindNextFile, SFileFindNextFile(this->handle(), &this->m_data->find_data) != false, ERROR_NO_MORE_FILES) == ERROR_NO_MORE_FILES) {
			if (this->m_data->handle) SFileFindClose(this->m_data->handle);
			this->m_data->handle = NULL;
			return false;
		}
		return true;
	}

	struct listfile_enumerator::data final : public base_data
	{
	public:
		archive archive;
		HANDLE handle;
		SFILE_FIND_DATA find_data;

		data() :
			handle(NULL)
		{
			memset(&this->find_data, 0, sizeof(this->find_data));
		}

		data(const data&) = delete;
		data(data&&) = delete;
		data& operator=(const data&) = delete;
		data& operator=(data&&) = delete;

	private:
		~data()
		{
			if (this->handle != NULL) SListFileFindClose(this->handle);
			this->handle;
		}
	};

	STORMLIB_PP_MAKE_CTOR_DTOR(listfile_enumerator);

	listfile_enumerator listfile_enumerator::create(const archive& archive, a_cstr mask, a_cstr listFile)
	{
		listfile_enumerator ret;
		ret.m_data = new listfile_enumerator::data();
		ret.m_data->archive = archive;
		STORMLIB_PP_LISTFILE_ENUM_FUNC_EX(&ret);
		if (STORMLIB_PP_CHECK_CALL(SListFileFindFirstFile, (ret.m_data->handle = SListFileFindFirstFile(ret.m_data->archive.handle(), listFile, mask, &ret.m_data->find_data)) != NULL, ERROR_NO_MORE_FILES) == ERROR_NO_MORE_FILES) {
			ret.m_data->handle = NULL;
		}
		return ret;
	}

	listfile_enumerator listfile_enumerator::create(const archive& archive, a_cstr listFile)
	{
		return create(archive, "*", listFile);
	}

	listfile_enumerator listfile_enumerator::create(const archive& archive, const astring& mask, const astring& listFile)
	{
		return create(archive, mask.c_str(), listFile.c_str());
	}

	listfile_enumerator listfile_enumerator::create(const archive& archive, const astring& listFile)
	{
		return create(archive, listFile.c_str());
	}

	listfile_enumerator listfile_enumerator::create(const archive& archive)
	{
		return create(archive, nullptr);
	}

	HANDLE listfile_enumerator::handle() const
	{
		return this->m_data->handle;
	}

	bool listfile_enumerator::is_valid() const
	{
		return this->m_data->handle != NULL;
	}

	a_cstr listfile_enumerator::file_name() const
	{
		if (!this->is_valid()) return nullptr;
		return this->m_data->find_data.cFileName;
	}

	a_cstr listfile_enumerator::plain_name() const
	{
		if (!this->is_valid()) return nullptr;
		return this->m_data->find_data.szPlainName;
	}

	std::uint32_t listfile_enumerator::hash_index() const
	{
		if (!this->is_valid()) return 0;
		return this->m_data->find_data.dwHashIndex;
	}

	std::uint32_t listfile_enumerator::block_index() const
	{
		if (!this->is_valid()) return 0;
		return this->m_data->find_data.dwBlockIndex;
	}

	std::uint32_t listfile_enumerator::file_size() const
	{
		if (!this->is_valid()) return 0;
		return this->m_data->find_data.dwFileSize;
	}

	file_flag listfile_enumerator::file_flags() const
	{
		if (!this->is_valid()) return file_flag::none;
		return static_cast<file_flag>(this->m_data->find_data.dwFileFlags);
	}

	std::uint32_t listfile_enumerator::compressed_size() const
	{
		if (!this->is_valid()) return 0;
		return this->m_data->find_data.dwCompSize;
	}

	std::uint64_t listfile_enumerator::file_time() const
	{
		if (!this->is_valid()) return 0;
		ULARGE_INTEGER ul;
		ul.LowPart = this->m_data->find_data.dwFileTimeLo;
		ul.HighPart = this->m_data->find_data.dwFileTimeHi;
		return ul.QuadPart;
	}

	LCID listfile_enumerator::locale() const
	{
		if (!this->is_valid()) return language_neutral;
		return this->m_data->find_data.lcLocale;
	}

	bool listfile_enumerator::next()
	{
		if (!this->is_valid()) return false;
		STORMLIB_PP_LISTFILE_ENUM_FUNC();
		if (STORMLIB_PP_CHECK_CALL(SListFileFindNextFile, SListFileFindNextFile(this->handle(), &this->m_data->find_data) != false, ERROR_NO_MORE_FILES) == ERROR_NO_MORE_FILES) {
			if (this->m_data->handle) SListFileFindClose(this->m_data->handle);
			this->m_data->handle = NULL;
			return false;
		}
		return true;
	}

#define STORMLIB_PP_MAKE_EXCEPTION(t, c, m) \
	a_cstr t::what() const { return (m); } \
	std::uint32_t t::code() const { return (c); }

	//windows
	STORMLIB_PP_MAKE_EXCEPTION(file_not_found_exception, ERROR_FILE_NOT_FOUND, u8"The system cannot find the file specified.");
	STORMLIB_PP_MAKE_EXCEPTION(access_denied_exception, ERROR_ACCESS_DENIED, u8"Access is denied.");
	STORMLIB_PP_MAKE_EXCEPTION(invalid_handle_exception, ERROR_INVALID_HANDLE, u8"The handle is invalid.");
	STORMLIB_PP_MAKE_EXCEPTION(not_supported_exception, ERROR_NOT_SUPPORTED, u8"The request is not supported.");
	STORMLIB_PP_MAKE_EXCEPTION(disk_full_exception, ERROR_DISK_FULL, u8"There is not enough space on the disk.");
	STORMLIB_PP_MAKE_EXCEPTION(already_exists_exception, ERROR_ALREADY_EXISTS, u8"Cannot create a file when that file already exists.");
	STORMLIB_PP_MAKE_EXCEPTION(insufficient_buffer_exception, ERROR_INSUFFICIENT_BUFFER, u8"The data area passed to a system call is too small.");
	STORMLIB_PP_MAKE_EXCEPTION(bad_format_exception, ERROR_BAD_FORMAT, u8"An attempt was made to load a program with an incorrect format.");
	STORMLIB_PP_MAKE_EXCEPTION(no_more_files_exception, ERROR_NO_MORE_FILES, u8"There are no more files.");
	STORMLIB_PP_MAKE_EXCEPTION(handle_eof_exception, ERROR_HANDLE_EOF, u8"Reached the end of the file");
	STORMLIB_PP_MAKE_EXCEPTION(can_not_complete_exception, ERROR_CAN_NOT_COMPLETE, u8"Cannot complete this function.");
	STORMLIB_PP_MAKE_EXCEPTION(file_corrupt_exception, ERROR_FILE_CORRUPT, u8"The file or directory is corrupted and unreadable.");
	//stormlib
	STORMLIB_PP_MAKE_EXCEPTION(avi_file_exception, ERROR_AVI_FILE, u8"The file is not a mpq archive, but an avi video.");
	STORMLIB_PP_MAKE_EXCEPTION(unknown_file_key_exception, ERROR_UNKNOWN_FILE_KEY, u8"The file key is not known.");
	STORMLIB_PP_MAKE_EXCEPTION(checksum_error_exception, ERROR_CHECKSUM_ERROR, u8"Checksum does not match.");
	STORMLIB_PP_MAKE_EXCEPTION(internal_file_exception, ERROR_INTERNAL_FILE, u8"The given operation is not allowed on internal file.");
	STORMLIB_PP_MAKE_EXCEPTION(base_file_missing_exception, ERROR_BASE_FILE_MISSING, u8"The file is present as incremental patch file, but base file is missing.");
	STORMLIB_PP_MAKE_EXCEPTION(marked_for_delete_exception, ERROR_MARKED_FOR_DELETE, u8"The file was marked as \"deleted\" in the MPQ");
	STORMLIB_PP_MAKE_EXCEPTION(file_incomplete_exception, ERROR_FILE_INCOMPLETE, u8"The required file part is missing");
	STORMLIB_PP_MAKE_EXCEPTION(unknown_file_names_exception, ERROR_UNKNOWN_FILE_NAMES, u8"A name of at least one file is unknown.");
	STORMLIB_PP_MAKE_EXCEPTION(cant_find_patch_prefix_exception, ERROR_CANT_FIND_PATCH_PREFIX, u8"StormLib was unable to find patch prefix for the patches.");

	unknown_exception::unknown_exception(std::uint32_t code) :
		m_code(code)
	{
	}

	a_cstr unknown_exception::what() const
	{
		return u8"Exception is unknown - seems to be a system specific error";
	}

	std::uint32_t unknown_exception::code() const
	{
		return this->m_code;
	}

	aggregate_exception::aggregate_exception(std::vector<std::exception_ptr>&& subExceptions, bool exceptionsLost) :
		m_subExceptions(std::forward<std::vector<std::exception_ptr>>(subExceptions)),
		m_exceptionsLost(exceptionsLost)
	{
	}

	a_cstr aggregate_exception::what() const
	{
		return u8"Multiple exceptions where thrown.";
	}

	const std::vector<std::exception_ptr>& aggregate_exception::sub_exceptions() const
	{
		return this->m_subExceptions;
	}

	bool aggregate_exception::exceptions_lost() const
	{
		return this->m_exceptionsLost;
	}
}