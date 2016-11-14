#include "StormLib.Net.h"
#include <msclr/gcroot.h>

using namespace System::Runtime::InteropServices;

#define STORMLIB_NET_FUNC_CTX(ctx)					local_exception_context _stromlib_lec(ctx)
#define STORMLIB_NET_FUNC_EX(ptr)					STORMLIB_NET_FUNC_CTX((ptr)->Context)
#define STORMLIB_NET_FUNC()							STORMLIB_NET_FUNC_EX(this)

#define STORMLIB_NET_CALL	_stormlib_call.invoke

#define STORMLIB_NET_MAKE_CALL_WRAPPER(keepLastError, func) \
	auto _stormlib_call = call_wrapper<decltype(&func)>::create<(keepLastError), &func>()

#define STORMLIB_NET_CHECK_CALL(func, call, ...) \
	{ \
	STORMLIB_NET_MAKE_CALL_WRAPPER(true, func); \
	auto _stormlib_val = (call); \
	static_assert(std::is_same<decltype(_stormlib_val), bool>::value, "result must be a bool"); \
	if(!_stormlib_val) _stromlib_lec.check_call<__VA_ARGS__>(_stormlib_call.error()); }

#define STORMLIB_NET_CHECK_CALL_INT(func, call, ...)	\
	{ \
	STORMLIB_NET_MAKE_CALL_WRAPPER(false, func); \
	auto _stromlib_val = (call); \
	static_assert(std::is_same<decltype(_stromlib_val), int>::value, "result must be a DWORD"); \
	_stromlib_lec.check_call<__VA_ARGS__>(static_cast<DWORD>(_stromlib_val)); }


#define STORMLIB_NET_CHECK_CALL_EX(errorVar, func, call, ...) \
	{ \
	STORMLIB_NET_MAKE_CALL_WRAPPER(true, func); \
	auto _stormlib_val = (call); \
	errorVar = _stormlib_call.error(); \
	static_assert(std::is_same<decltype(_stormlib_val), bool>::value, "result must be a bool"); \
	static_assert(std::is_same<decltype(errorVar), DWORD>::value, "errorVar must be a DWORD"); \
	if(!_stormlib_val) errorVar = _stromlib_lec.check_call<__VA_ARGS__>(errorVar); }

#define STORMLIB_NET_THROW_LENGTH_MISMATCH() \
	_stromlib_lec.throw_length_mismatch()

#define STORMLIB_NET_GET_PROPERTY_INT32(key)			get_property_int32(this->Context, this->m_handle, (key))
#define STORMLIB_NET_GET_PROPERTY_INT64(key)			get_property_int64(this->Context, this->m_handle, (key))
#define STORMLIB_NET_GET_PROPERTY_BYTE_ARRAY(key)		get_property_byte_array(this->Context, this->m_handle, (key))
#define STROMLIB_NET_GET_PROPERTY_TSTRING(key)			get_property_string<TCHAR>(this->Context, this->m_handle, (key))
#define STORMLIB_NET_GET_PROPERTY_ENUM(key, type, mask)	get_property_enum<type>(this->Context, this->m_handle, (key), (mask))
#define STORMLIB_NET_GET_PROPERTY_DATETIME(key)			get_property_date_time(this->Context, this->m_handle, (key))

#define STORMLIB_NET_UNEXPECTED			0x000FFFFF
#define STORMLIB_NET_EXCEPTION_CAUGHT	0x000EEEEE

static_assert(sizeof(DWORD) == sizeof(std::uint32_t), "size mismatch");
static_assert(std::is_unsigned<DWORD>::value == std::is_unsigned<std::uint32_t>::value, "sign mismatch");

namespace StormLib
{
	namespace Net
	{
		namespace
		{
#pragma managed(push, off)
			template<bool KeepLastError, typename TFunc, TFunc Func, typename TReturn, typename... TArgs>
			struct call_wrapper_impl;

			template<typename TFunc, TFunc Func, typename TReturn, typename... TArgs>
			struct call_wrapper_impl<false, TFunc, Func, TReturn, TArgs...>
			{
			public:
				call_wrapper_impl() = default;
				call_wrapper_impl(const call_wrapper_impl&) = default;
				call_wrapper_impl(call_wrapper_impl&&) = default;
				call_wrapper_impl& operator=(const call_wrapper_impl&) = default;
				call_wrapper_impl& operator=(call_wrapper_impl&&) = default;
				~call_wrapper_impl() = default;

				TReturn invoke(TArgs... args) noexcept
				{
					return Func(args...);
				}
			};

			template<typename TFunc, TFunc Func, typename TReturn, typename... TArgs>
			struct call_wrapper_impl<true, TFunc, Func, TReturn, TArgs...>
			{
			private:
				DWORD m_error;

			public:
				call_wrapper_impl() noexcept :
					m_error(ERROR_SUCCESS)
				{
				}

				call_wrapper_impl(const call_wrapper_impl&) = default;
				call_wrapper_impl(call_wrapper_impl&&) = default;
				call_wrapper_impl& operator=(const call_wrapper_impl&) = default;
				call_wrapper_impl& operator=(call_wrapper_impl&&) = default;
				~call_wrapper_impl() = default;

				TReturn invoke(TArgs... args) noexcept
				{
					SetLastError(0);
					TReturn ret = Func(args...);
					this->m_error = GetLastError();
					return ret;
				}

				DWORD error() const noexcept
				{
					return this->m_error;
				}
			};

			template<typename T>
			struct call_wrapper;

			template<typename TReturn, typename... TArgs>
			struct call_wrapper<TReturn(WINAPI*)(TArgs...)>
			{
				template<bool KeepLastError, TReturn(WINAPI * Func)(TArgs...)>
				static auto create()
				{
					return call_wrapper_impl<KeepLastError, TReturn(WINAPI*)(TArgs...), Func, TReturn, TArgs...>();
				}
			};
#pragma managed(pop)

			Int32 to_int32(std::uint32_t value)
			{
				static_assert(sizeof(Int32) == sizeof(std::uint32_t), "size mismatch");
				return *reinterpret_cast<const Int32*>(&value);
			}

			std::uint32_t from_int32(Int32 value)
			{
				static_assert(sizeof(Int32) == sizeof(std::uint32_t), "size mismatch");
				return *reinterpret_cast<const std::uint32_t*>(&value);
			}

			Int64 to_int64(std::uint64_t value)
			{
				static_assert(sizeof(Int64) == sizeof(std::uint64_t), "size mismatch");
				return *reinterpret_cast<const Int64*>(&value);
			}

			std::uint64_t from_int64(Int64 value)
			{
				static_assert(sizeof(Int64) == sizeof(std::uint64_t), "size mismatch");
				return *reinterpret_cast<const std::uint64_t*>(&value);
			}

			String^ to_string(const stormlib::astring& value)
			{
				return gcnew String(value.c_str());
			}

			String^ to_string(const stormlib::wstring& value)
			{
				return gcnew String(value.c_str());
			}

			String^ to_string(stormlib::a_cstr value)
			{
				return value ? gcnew String(value) : nullptr;
			}

			String^ to_string(stormlib::w_cstr value)
			{
				return value ? gcnew String(value) : nullptr;
			}

			DateTime to_datetime(std::uint64_t value)
			{
				return DateTime::FromFileTime(to_int64(value));
			}

			std::uint64_t from_datetime(DateTime value)
			{
				return from_int64(value.ToFileTime());
			}

			struct astring_handle final
			{
			private:
				IntPtr m_ptr;

			public:
				explicit astring_handle(String^ value) :
					m_ptr(nullptr)
				{
					if (value) this->m_ptr = Marshal::StringToHGlobalAnsi(value);
				}

				astring_handle(const astring_handle&) = delete;
				astring_handle(astring_handle&&) = delete;
				astring_handle& operator=(const astring_handle&) = delete;
				astring_handle& operator=(astring_handle&&) = delete;

				~astring_handle()
				{
					if (this->m_ptr.ToPointer()) Marshal::FreeHGlobal(this->m_ptr);
					this->m_ptr = IntPtr(nullptr);
				}

				stormlib::a_cstr c_str()
				{
					return reinterpret_cast<stormlib::a_cstr>(this->m_ptr.ToPointer());
				}
			};

			struct wstring_handle final
			{
			private:
				IntPtr m_ptr;

			public:
				explicit wstring_handle(String^ value) :
					m_ptr(nullptr)
				{
					if (value) this->m_ptr = Marshal::StringToHGlobalUni(value);
				}

				wstring_handle(const wstring_handle&) = delete;
				wstring_handle(wstring_handle&&) = delete;
				wstring_handle& operator=(const wstring_handle&) = delete;
				wstring_handle& operator=(wstring_handle&&) = delete;

				~wstring_handle()
				{
					if (this->m_ptr.ToPointer()) Marshal::FreeHGlobal(this->m_ptr);
					this->m_ptr = IntPtr(nullptr);
				}

				stormlib::w_cstr c_str()
				{
					return reinterpret_cast<stormlib::w_cstr>(this->m_ptr.ToPointer());
				}
			};

			template<DWORD... Errors>
			struct error_filter;

			template<DWORD Curr, DWORD... Rem>
			struct error_filter<Curr, Rem...>
			{
				static bool failure(DWORD code)
				{
					return code != Curr && error_filter<Rem...>::failure(code);
				}
			};

			template<>
			struct error_filter<>
			{
				static bool failure(DWORD code)
				{
					return code != ERROR_SUCCESS;
				}
			};

			struct local_exception_context final
			{
			private:
				msclr::gcroot<ExceptionContext^> m_context;

				template<typename T>
				__declspec(noreturn) void throw_exception(T^ ex)
				{
					if (this->m_context != nullptr) this->m_context->ThrowException(ex);
					throw ex;
				}

			public:
				explicit local_exception_context(ExceptionContext^ context) :
					m_context(context)
				{
				}

				local_exception_context(const local_exception_context&) = delete;
				local_exception_context(local_exception_context&&) = delete;
				local_exception_context& operator=(const local_exception_context&) = delete;
				local_exception_context& operator=(local_exception_context&&) = delete;
				~local_exception_context() = default;

				template<DWORD... Skip>
				DWORD check_call(DWORD error)
				{
					if (error_filter<Skip...>::failure(error)) {
						switch (error) {
						case ERROR_AVI_FILE:
							this->throw_exception(gcnew AviFileException());
							break;
						case ERROR_UNKNOWN_FILE_KEY:
							this->throw_exception(gcnew UnknownFileKeyException());
							break;
						case ERROR_CHECKSUM_ERROR:
							this->throw_exception(gcnew ChecksumErrorException());
							break;
						case ERROR_INTERNAL_FILE:
							this->throw_exception(gcnew InternalFileException());
							break;
						case ERROR_BASE_FILE_MISSING:
							this->throw_exception(gcnew BaseFileMissingException());
							break;
						case ERROR_MARKED_FOR_DELETE:
							this->throw_exception(gcnew MarkedForDeleteException());
							break;
						case ERROR_FILE_INCOMPLETE:
							this->throw_exception(gcnew FileIncompleteException());
							break;
						case ERROR_UNKNOWN_FILE_NAMES:
							this->throw_exception(gcnew UnknownFileNamesException());
							break;
						case ERROR_CANT_FIND_PATCH_PREFIX:
							this->throw_exception(gcnew CantFindPatchPrefixException());
							break;
						case STORMLIB_NET_EXCEPTION_CAUGHT:
							break;
						case STORMLIB_NET_UNEXPECTED:
							this->throw_exception(Marshal::GetExceptionForHR(E_UNEXPECTED));
							break;
						default:
							if (error <= 0xFFFF) this->throw_exception(Marshal::GetExceptionForHR(__HRESULT_FROM_WIN32(error)));
							else this->throw_exception(Marshal::GetExceptionForHR(E_UNEXPECTED));
							break;
						}
					}
					return error;
				}

				__declspec(noreturn) void throw_length_mismatch()
				{
					this->throw_exception(gcnew InvalidOperationException("length mismatch"));
				}
			};

			typedef std::conditional_t<std::is_same<TCHAR, WCHAR>::value, wstring_handle, astring_handle> tstring_handle;

			void get_property_raw(ExceptionContext^ ctx, HANDLE handle, SFileInfoClass key, void* ptr, DWORD size)
			{
				STORMLIB_NET_FUNC_CTX(ctx);
				DWORD len;
				STORMLIB_NET_CHECK_CALL(SFileGetFileInfo, STORMLIB_NET_CALL(handle, key, ptr, size, &len) != false);
				if (len != size) STORMLIB_NET_THROW_LENGTH_MISMATCH();
			}

			DWORD get_property_size(ExceptionContext^ ctx, HANDLE handle, SFileInfoClass key)
			{
				STORMLIB_NET_FUNC_CTX(ctx);
				DWORD len;
				STORMLIB_NET_CHECK_CALL(SFileGetFileInfo, STORMLIB_NET_CALL(handle, key, nullptr, 0, &len) != false);
				return len;
			}

			Int32 get_property_int32(ExceptionContext^ ctx, HANDLE handle, SFileInfoClass key)
			{
				std::uint32_t ret;
				get_property_raw(ctx, handle, key, &ret, sizeof(ret));
				return to_int32(ret);
			}

			Int64 get_property_int64(ExceptionContext^ ctx, HANDLE handle, SFileInfoClass key)
			{
				std::uint64_t ret;
				get_property_raw(ctx, handle, key, &ret, sizeof(ret));
				return to_int64(ret);
			}

			array<Byte>^ get_property_byte_array(ExceptionContext^ ctx, HANDLE handle, SFileInfoClass key)
			{
				DWORD s = get_property_size(ctx, handle, key);
				array<Byte>^ ret = gcnew array<Byte>(to_int32(s / sizeof(Byte)));
				if (ret->Length > 0) {
					pin_ptr<Byte> ptr = &ret[0];
					get_property_raw(ctx, handle, key, ptr, (s / sizeof(Byte)) * sizeof(Byte));
				}
				return ret;
			}

			template<typename TChar>
			String^ get_property_string(ExceptionContext^ ctx, HANDLE handle, SFileInfoClass key)
			{
				DWORD s = get_property_size(ctx, handle, key) / sizeof(TChar);
				if (s <= 0) return "";
				std::unique_ptr<TChar[]> buffer(new TChar[s]);
				get_property_raw(ctx, handle, key, buffer.get(), s * sizeof(TChar));
				return to_string(buffer.get());
			}

			template<typename TEnum>
			TEnum get_property_enum(ExceptionContext^ ctx, HANDLE handle, SFileInfoClass key, DWORD mask)
			{
				DWORD ret;
				get_property_raw(ctx, handle, key, &ret, sizeof(ret));
				return static_cast<TEnum>(ret & mask);
			}

			DateTime get_property_date_time(ExceptionContext^ ctx, HANDLE handle, SFileInfoClass key)
			{
				std::uint64_t ret;
				get_property_raw(ctx, handle, key, &ret, sizeof(ret));
				return to_datetime(ret);
			}

			template<typename T>
			bool operator==(const msclr::gcroot<T>& x, nullptr_t)
			{
				return static_cast<T>(x) == nullptr;
			}

			template<typename T>
			bool operator!=(const msclr::gcroot<T>& x, nullptr_t)
			{
				return static_cast<T>(x) != nullptr;
			}

			template<typename T>
			bool operator==(nullptr_t, const msclr::gcroot<T>& y)
			{
				return static_cast<T>(y) == nullptr;
			}

			template<typename T>
			bool operator!=(nullptr_t, const msclr::gcroot<T>& y)
			{
				return static_cast<T>(y) != nullptr;
			}

			struct add_file_callback_wrapper final
			{
			private:
				msclr::gcroot<ExceptionContext^> m_context;
				msclr::gcroot<AddFileCallback^> m_callback;
				HANDLE m_handle;

				static void WINAPI invoke_callback(void * pvUserData, DWORD dwBytesWritten, DWORD dwTotalBytes, bool bFinalCall)
				{
					if (pvUserData) reinterpret_cast<add_file_callback_wrapper*>(pvUserData)->invoke(dwBytesWritten, dwTotalBytes, bFinalCall);
				}

				void invoke(std::uint32_t bytesWritten, std::uint32_t totalBytes, bool finalCall) noexcept
				{
					try {
						try {
							this->m_callback->Invoke(to_int32(bytesWritten), to_int32(totalBytes), finalCall);
						}
						catch (Exception^ e) {
							SetLastError(this->m_context->Add(e));
						}
					}
					catch (...) {
						//swallow silently
						SetLastError(STORMLIB_NET_UNEXPECTED);
					}
				}

			public:
				add_file_callback_wrapper(ExceptionContext^ context, HANDLE handle, AddFileCallback^ callback) :
					m_context(context),
					m_handle(handle),
					m_callback(callback)
				{
					if (!context) throw gcnew ArgumentNullException("context");
					if (!callback) this->m_handle = NULL;
					if (this->m_handle) SFileSetAddFileCallback(this->m_handle, &invoke_callback, this);
				}

				add_file_callback_wrapper(const add_file_callback_wrapper&) = delete;
				add_file_callback_wrapper(add_file_callback_wrapper&&) = delete;
				add_file_callback_wrapper& operator=(const add_file_callback_wrapper&) = delete;
				add_file_callback_wrapper& operator=(add_file_callback_wrapper&&) = delete;

				~add_file_callback_wrapper()
				{
					if (this->m_handle) SFileSetAddFileCallback(this->m_handle, nullptr, nullptr);
					this->m_handle = nullptr;
				}

				void done()
				{
					this->m_context->Check();
				}
			};

			struct compact_callback_wrapper final
			{
			private:
				msclr::gcroot<ExceptionContext^> m_context;
				msclr::gcroot<CompactProgressCallback^> m_checkingFilesCallback;
				msclr::gcroot<CompactProgressCallback^> m_checkingHashTableCallback;
				msclr::gcroot<CompactProgressCallback^> m_copyingNonMpqDataCallback;
				msclr::gcroot<CompactProgressCallback^> m_compactingArchveCallback;
				msclr::gcroot<CompactProgressCallback^> m_closingArchiveCallback;
				HANDLE m_handle;

				static void WINAPI invoke_callback(void * pvUserData, DWORD dwWorkType, ULONGLONG BytesProcessed, ULONGLONG TotalBytes)
				{
					if (pvUserData) reinterpret_cast<compact_callback_wrapper*>(pvUserData)->invoke(dwWorkType, BytesProcessed, TotalBytes);
				}

				void invoke(std::uint32_t workType, std::uint64_t processed, std::uint64_t total) noexcept
				{
					try {
						try {
							switch (workType) {
							case CCB_CHECKING_FILES:
								if (this->m_checkingFilesCallback != nullptr) this->m_checkingFilesCallback->Invoke(to_int64(processed), to_int64(total));
								break;
							case CCB_CHECKING_HASH_TABLE:
								if (this->m_checkingHashTableCallback != nullptr) this->m_checkingHashTableCallback->Invoke(to_int64(processed), to_int64(total));
								break;
							case CCB_CLOSING_ARCHIVE:
								if (this->m_closingArchiveCallback != nullptr) this->m_closingArchiveCallback->Invoke(to_int64(processed), to_int64(total));
								break;
							case CCB_COMPACTING_FILES:
								if (this->m_compactingArchveCallback != nullptr) this->m_compactingArchveCallback->Invoke(to_int64(processed), to_int64(total));
								break;
							case CCB_COPYING_NON_MPQ_DATA:
								if (this->m_copyingNonMpqDataCallback != nullptr) this->m_copyingNonMpqDataCallback->Invoke(to_int64(processed), to_int64(total));
								break;
							}
						}
						catch (Exception^ e) {
							SetLastError(this->m_context->Add(e));
						}
					}
					catch (...) {
						//swallow silently
						SetLastError(STORMLIB_NET_UNEXPECTED);
					}
				}

			public:
				compact_callback_wrapper(ExceptionContext^ context, HANDLE handle, CompactCallback^ callback) :
					m_context(context),
					m_handle(handle),
					m_checkingFilesCallback(callback ? callback->CheckingFiles : nullptr),
					m_checkingHashTableCallback(callback ? callback->CheckingHashTable : nullptr),
					m_copyingNonMpqDataCallback(callback ? callback->CopyingNonMpqData : nullptr),
					m_compactingArchveCallback(callback ? callback->CompactingArchve : nullptr),
					m_closingArchiveCallback(callback ? callback->ClosingArchive : nullptr)
				{
					if (!context) throw gcnew ArgumentNullException("context");
					if (this->m_checkingFilesCallback == nullptr &&
						this->m_checkingHashTableCallback == nullptr &&
						this->m_copyingNonMpqDataCallback == nullptr &&
						this->m_compactingArchveCallback == nullptr &&
						this->m_closingArchiveCallback == nullptr) {
						this->m_handle = NULL;
					}
					if (this->m_handle) SFileSetCompactCallback(this->m_handle, &invoke_callback, this);
				}

				compact_callback_wrapper(const compact_callback_wrapper&) = delete;
				compact_callback_wrapper(compact_callback_wrapper&&) = delete;
				compact_callback_wrapper& operator=(const compact_callback_wrapper&) = delete;
				compact_callback_wrapper& operator=(compact_callback_wrapper&&) = delete;

				~compact_callback_wrapper()
				{
					if (this->m_handle) SFileSetCompactCallback(this->m_handle, nullptr, nullptr);
					this->m_handle = nullptr;
				}

				void done()
				{
					this->m_context->Check();
				}
			};
		}

		Int32 Constants::Version::get()
		{
			return to_int32(stormlib::version);
		}

		String^ Constants::VersionString::get()
		{
			if (!s_versionString) s_versionString = to_string(stormlib::version_string);
			return s_versionString;
		}

		Int32 Constants::IdMpq::get()
		{
			return to_int32(stormlib::id_mpq);
		}

		Int32 Constants::IdMpqUserdata::get()
		{
			return to_int32(stormlib::id_mpq_userdata);
		}

		Int32 Constants::IdMpk::get()
		{
			return to_int32(stormlib::id_mpk);
		}

		Int32 Constants::HashTableSizeMin::get()
		{
			return to_int32(stormlib::hash_table_size_min);
		}

		Int32 Constants::HashTableSizeDefault::get()
		{
			return to_int32(stormlib::hash_table_size_default);
		}

		Int32 Constants::HashTableSizeMax::get()
		{
			return to_int32(stormlib::hash_table_size_max);
		}

		String^ Constants::ListfileName::get()
		{
			if (!s_listfileName) s_listfileName = to_string(stormlib::listfile_name);
			return s_listfileName;
		}

		String^ Constants::SignatureName::get()
		{
			if (!s_signatureName) s_signatureName = to_string(stormlib::signature_name);
			return s_signatureName;
		}

		String^ Constants::AttributesName::get()
		{
			if (!s_attributesName) s_attributesName = to_string(stormlib::attributes_name);
			return s_attributesName;
		}

		String^ Constants::PatchMetadataName::get()
		{
			if (!s_patchMetadataName) s_patchMetadataName = to_string(stormlib::patch_metadata_name);
			return s_patchMetadataName;
		}

		Int32 Constants::LanguageNeutral::get()
		{
			return to_int32(stormlib::language_neutral);
		}

		CreateMpq::CreateMpq()
		{
			stormlib::create_mpq data;
			this->Version = static_cast<MpqFormatVersion>(data.version);
			this->BaseProvider = static_cast<Net::BaseProvider>(data.base_provider);
			this->StreamProvider = static_cast<Net::StreamProvider>(data.stream_provider);
			this->StreamFlags = static_cast<Net::StreamFlag>(data.stream_flags);
			this->ListfileFlags = static_cast<Net::FileFlag>(data.listfile_flags);
			this->AttributesFlags = static_cast<Net::FileFlag>(data.attributes_flags);
			this->SignatureFlags = static_cast<Net::FileFlag>(data.signature_flags);
			this->FileAttributes = static_cast<Net::AttributeFlag>(data.file_attributes);
			this->SectorSize = to_int32(data.sector_size);
			this->RawChunkSize = to_int32(data.raw_chunk_size);
			this->MaxFileCount = to_int32(data.max_file_count);
		}

		struct raw_stream_provider_wrapper final
		{
		private:
			msclr::gcroot<ExceptionContext^> m_context;
			msclr::gcroot<IStreamProvider^> m_provider;
			TStreamProvider m_impl;

			static bool WINAPI read_stream(void * pData, ULONGLONG ByteOffset, void * pvBuffer, DWORD dwBytesToRead, DWORD* pBytesRead)
			{
				if (!pData || !pvBuffer) {
					SetLastError(ERROR_INVALID_PARAMETER);
					return false;
				}
				return reinterpret_cast<raw_stream_provider_wrapper*>(pData)->read(ByteOffset, pvBuffer, dwBytesToRead, *reinterpret_cast<std::uint32_t*>(pBytesRead));
			}

			static bool WINAPI write_stream(void * pData, ULONGLONG ByteOffset, const void * pvBuffer, DWORD dwBytesToWrite, DWORD* pBytesWritten)
			{
				if (!pData || !pvBuffer) {
					SetLastError(ERROR_INVALID_PARAMETER);
					return false;
				}
				return reinterpret_cast<raw_stream_provider_wrapper*>(pData)->write(ByteOffset, pvBuffer, dwBytesToWrite, *reinterpret_cast<std::uint32_t*>(pBytesWritten));
			}

			static bool WINAPI resize_stream(void * pData, ULONGLONG NewSize)
			{
				if (!pData) {
					SetLastError(ERROR_INVALID_PARAMETER);
					return false;
				}
				return reinterpret_cast<raw_stream_provider_wrapper*>(pData)->resize_stream(pData, NewSize);
			}

			bool read(std::uint64_t byteOffset, void* buffer, std::uint32_t toRead, std::uint32_t& read) noexcept
			{
				try {
					try {
						if (toRead <= 0) {
							read = 0;
							return true;
						}
						read = from_int32(this->m_provider->Read(to_int64(byteOffset), IntPtr(buffer), to_int32(toRead)));
						return true;
					}
					catch (Exception^ e) {
						SetLastError(this->m_context->Add(e));
						return false;
					}
				}
				catch (...) {
					//swallow silently
					SetLastError(STORMLIB_NET_UNEXPECTED);
					return false;
				}
			}

			bool write(std::uint64_t byteOffset, const void* buffer, std::uint32_t toWrite, std::uint32_t& written) noexcept
			{
				try {
					try {
						if (toWrite <= 0) {
							written = 0;
							return true;
						}
						written = from_int32(this->m_provider->Write(to_int64(byteOffset), IntPtr(const_cast<void*>(buffer)), to_int32(toWrite)));
						return true;
					}
					catch (Exception^ e) {
						SetLastError(this->m_context->Add(e));
						return false;
					}
				}
				catch (...) {
					//swallow silently
					SetLastError(STORMLIB_NET_UNEXPECTED);
					return false;
				}
			}

			bool resize(std::uint64_t newSize) noexcept
			{
				try {
					try {
						this->m_provider->Resize(to_int64(newSize));
					}
					catch (Exception^ e) {
						SetLastError(this->m_context->Add(e));
						return false;
					}
				}
				catch (...) {
					//swallow silently
					SetLastError(STORMLIB_NET_UNEXPECTED);
					return false;
				}
			}

		public:
			raw_stream_provider_wrapper(ExceptionContext^ context, IStreamProvider^ provider) :
				m_context(context),
				m_provider(provider)
			{
				if (!context) throw gcnew ArgumentNullException("context");
				if (!provider) throw gcnew ArgumentNullException("provider");
				this->m_impl.pData = this;
				this->m_impl.Read = &read_stream;
				this->m_impl.Resize = &resize_stream;
				this->m_impl.Write = &write_stream;
			}

			raw_stream_provider_wrapper(const raw_stream_provider_wrapper&) = delete;
			raw_stream_provider_wrapper(raw_stream_provider_wrapper&&) = delete;
			raw_stream_provider_wrapper& operator=(const raw_stream_provider_wrapper&) = delete;
			raw_stream_provider_wrapper& operator=(raw_stream_provider_wrapper&&) = delete;
			~raw_stream_provider_wrapper() = default;

			TStreamProvider* impl()
			{
				return &this->m_impl;
			}

			IStreamProvider^ provider()
			{
				return this->m_provider;
			}
		};

		struct raw_stream_provider_factory_wrapper final
		{
		private:
			msclr::gcroot<ExceptionContext^> m_context;
			msclr::gcroot<IStreamProviderFactory^> m_factory;
			TStreamProviderFactory m_impl;

			static bool WINAPI create_stream(void * pData, const TCHAR * szFileName, bool ShareWrite, TStreamProvider ** ppProvider)
			{
				if (!pData || !szFileName || !ppProvider) {
					SetLastError(ERROR_INVALID_PARAMETER);
					return false;
				}
				return reinterpret_cast<raw_stream_provider_factory_wrapper*>(pData)->create(szFileName, ShareWrite, *ppProvider);
			}

			static bool WINAPI open_stream(void * pData, const TCHAR * szFileName, bool ReadOnly, bool ShareWrite, TStreamProvider ** ppProvider, ULONGLONG* pFileSize, ULONGLONG* pFileTime)
			{
				if (!pData || !szFileName || !ppProvider || !pFileSize || !pFileTime) {
					SetLastError(ERROR_INVALID_PARAMETER);
					return false;
				}
				return reinterpret_cast<raw_stream_provider_factory_wrapper*>(pData)->open(szFileName, ReadOnly, ShareWrite, *ppProvider, *pFileSize, *pFileTime);
			}

			static bool WINAPI close_stream(void * pData, TStreamProvider * pProvider)
			{
				if (!pData || !pProvider) {
					SetLastError(ERROR_INVALID_PARAMETER);
					return false;
				}
				return reinterpret_cast<raw_stream_provider_factory_wrapper*>(pData)->close(pProvider);
			}

			bool create(stormlib::t_cstr fileName, bool shareWrite, TStreamProvider*& provider) noexcept
			{
				try {
					try {
						std::unique_ptr<raw_stream_provider_wrapper> ptr(new raw_stream_provider_wrapper(this->m_context, this->m_factory->Create(to_string(fileName), shareWrite)));
						provider = ptr->impl();
						ptr.release();
						return true;
					}
					catch (Exception^ e) {
						SetLastError(this->m_context->Add(e));
						return false;
					}
				}
				catch (...) {
					//swallow silently
					SetLastError(STORMLIB_NET_UNEXPECTED);
					return false;
				}
			}

			bool open(stormlib::t_cstr fileName, bool readOnly, bool shareWrite, TStreamProvider*& provider, std::uint64_t& fileSize, std::uint64_t& fileTime) noexcept
			{
				try {
					try {
						IStreamProvider^ mProvider;
						Int64 mFileSize;
						DateTime mFileTime;
						this->m_factory->Open(to_string(fileName), readOnly, shareWrite, mProvider, mFileSize, mFileTime);
						fileSize = from_int64(mFileSize);
						fileTime = from_datetime(mFileTime);
						std::unique_ptr<raw_stream_provider_wrapper> ptr(new raw_stream_provider_wrapper(this->m_context, mProvider));
						provider = ptr->impl();
						ptr.release();
						return true;
					}
					catch (Exception^ e) {
						SetLastError(this->m_context->Add(e));
						return false;
					}
				}
				catch (...) {
					//swallow silently
					SetLastError(STORMLIB_NET_UNEXPECTED);
					return false;
				}
			}

			bool close(TStreamProvider* provider) noexcept
			{
				try {
					try {
						raw_stream_provider_wrapper* wrapper = reinterpret_cast<raw_stream_provider_wrapper*>(provider->pData);
						try {
							this->m_factory->Close(wrapper->provider());
						}
						finally {
							delete wrapper;
						}
						return true;
					}
					catch (Exception^ e) {
						SetLastError(this->m_context->Add(e));
						return false;
					}
				}
				catch (...) {
					//swallow silently
					SetLastError(STORMLIB_NET_UNEXPECTED);
					return false;
				}
			}

		public:
			raw_stream_provider_factory_wrapper(ExceptionContext^ context, IStreamProviderFactory^ factory) :
				m_context(context),
				m_factory(factory)
			{
				if (!context) throw gcnew ArgumentNullException("context");
				if (!factory) throw gcnew ArgumentNullException("factory");
				this->m_impl.Close = &close_stream;
				this->m_impl.Create = &create_stream;
				this->m_impl.Open = &open_stream;
				this->m_impl.pData = this;
			}

			raw_stream_provider_factory_wrapper(const raw_stream_provider_factory_wrapper&) = delete;
			raw_stream_provider_factory_wrapper(raw_stream_provider_factory_wrapper&&) = delete;
			raw_stream_provider_factory_wrapper& operator=(const raw_stream_provider_factory_wrapper&) = delete;
			raw_stream_provider_factory_wrapper& operator=(raw_stream_provider_factory_wrapper&&) = delete;
			~raw_stream_provider_factory_wrapper() = default;

			TStreamProviderFactory* impl()
			{
				return &this->m_impl;
			}
		};

		ExceptionContext::ExceptionContext()
		{
			this->m_exceptions = gcnew Generic::List<Exception^>();
		}

		UInt32 ExceptionContext::Add(Exception^ ex)
		{
			if (ex) {
				this->m_exceptions->Add(ex);
				HRESULT hres = ex->HResult;
				if (HRESULT_FACILITY(hres) == FACILITY_WIN32) return HRESULT_CODE(hres);
				else return STORMLIB_NET_EXCEPTION_CAUGHT;
			}
			return STORMLIB_NET_UNEXPECTED;
		}

		void ExceptionContext::ThrowException(Exception^ ex)
		{
			if (!ex) throw gcnew ArgumentNullException("ex");
			if (this->m_exceptions->Count <= 0) throw ex;
			this->m_exceptions->Add(ex);
			throw gcnew AggregateException(this->m_exceptions->ToArray());
		}

		void ExceptionContext::Check()
		{
			if (this->m_exceptions->Count > 0) throw gcnew AggregateException(this->m_exceptions->ToArray());
		}

		Archive::Archive(IStreamProviderFactory^ factory) :
			m_handle(NULL),
			m_factory(nullptr)
		{
			this->m_context = gcnew ExceptionContext();
			if (factory) this->m_factory = new raw_stream_provider_factory_wrapper(this->m_context, factory);
		}

		ExceptionContext^ Archive::Context::get()
		{
			return this->m_context;
		}

		Archive::!Archive()
		{
			if (this->m_handle != NULL) SFileCloseArchive(this->m_handle);
			this->m_handle = NULL;
			if (this->m_factory) delete this->m_factory;
			this->m_factory = nullptr;
		}

		Archive::~Archive()
		{
			this->!Archive();
		}

		Int32 Archive::GetLocale()
		{
			return to_int32(stormlib::get_locale());
		}

		Int32 Archive::SetLocale(Int32 newLocale)
		{
			return to_int32(stormlib::set_locale(from_int32(newLocale)));
		}

		Archive^ Archive::Open(IStreamProviderFactory^ factory, String^ mpqName, Net::BaseProvider baseProvider, StreamProvider streamProvider, StreamFlag streamFlags, MpqOpenFlag flags)
		{
			if (!mpqName) throw gcnew ArgumentNullException("mpqName");
			Archive^ ret = gcnew Archive(factory);
			STORMLIB_NET_FUNC_EX(ret);
			tstring_handle mpqNameH(mpqName);
			pin_ptr<HANDLE> handlePtr = &ret->m_handle;
			STORMLIB_NET_CHECK_CALL(SFileOpenArchive, STORMLIB_NET_CALL(ret->m_factory ? ret->m_factory->impl() : nullptr, mpqNameH.c_str(), 0, static_cast<DWORD>(baseProvider) | static_cast<DWORD>(streamProvider) | static_cast<DWORD>(streamFlags) | static_cast<DWORD>(flags), handlePtr) != false);
			return ret;
		}

		Archive^ Archive::Create(IStreamProviderFactory^ factory, String^ mpqName, MpqCreateFlag flags, Int32 maxFileCount)
		{
			if (!mpqName) throw gcnew ArgumentNullException("mpqName");
			Archive^ ret = gcnew Archive(factory);
			STORMLIB_NET_FUNC_EX(ret);
			tstring_handle mpqNameH(mpqName);
			pin_ptr<HANDLE> handlePtr = &ret->m_handle;
			STORMLIB_NET_CHECK_CALL(SFileCreateArchive, STORMLIB_NET_CALL(ret->m_factory ? ret->m_factory->impl() : nullptr, mpqNameH.c_str(), static_cast<DWORD>(flags), from_int32(maxFileCount), handlePtr) != false);
			return ret;
		}

		Archive^ Archive::Create(IStreamProviderFactory^ factory, String^ mpqName, CreateMpq^ data)
		{
			if (!mpqName) throw gcnew ArgumentNullException("mpqName");
			if (!data) throw gcnew ArgumentNullException("data");
			SFILE_CREATE_MPQ d;
			memset(&d, 0, sizeof(d));
			d.cbSize = sizeof(d);
			d.dwAttrFlags = static_cast<DWORD>(data->FileAttributes);
			d.dwFileFlags1 = static_cast<DWORD>(data->ListfileFlags);
			d.dwFileFlags2 = static_cast<DWORD>(data->AttributesFlags);
			d.dwFileFlags3 = static_cast<DWORD>(data->SignatureFlags);
			d.dwMaxFileCount = from_int32(data->MaxFileCount);
			d.dwMpqVersion = static_cast<DWORD>(data->Version);
			d.dwRawChunkSize = from_int32(data->RawChunkSize);
			d.dwSectorSize = from_int32(data->SectorSize);
			d.dwStreamFlags = static_cast<DWORD>(data->BaseProvider) | static_cast<DWORD>(data->StreamProvider) | static_cast<DWORD>(data->StreamFlags);
			Archive^ ret = gcnew Archive(factory);
			STORMLIB_NET_FUNC_EX(ret);
			tstring_handle mpqNameH(mpqName);
			pin_ptr<HANDLE> handlePtr = &ret->m_handle;
			STORMLIB_NET_CHECK_CALL(SFileCreateArchive2, STORMLIB_NET_CALL(ret->m_factory ? ret->m_factory->impl() : nullptr, mpqNameH.c_str(), &d, handlePtr) != false);
			return ret;
		}

		StormLib::Net::CompactCallback^ Archive::CompactCallback::get()
		{
			return this->m_compactCallback;
		}

		void Archive::CompactCallback::set(StormLib::Net::CompactCallback^ value)
		{
			this->m_compactCallback = value;
		}

		StormLib::Net::AddFileCallback^ Archive::AddFileCallback::get()
		{
			return this->m_addFileCallback;
		}

		void Archive::AddFileCallback::set(StormLib::Net::AddFileCallback^ value)
		{
			this->m_addFileCallback = value;
		}

		Int32 Archive::MaxFileCount::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileMpqMaxFileCount);
		}

		void Archive::MaxFileCount::set(Int32 value)
		{
			STORMLIB_NET_FUNC();
			STORMLIB_NET_CHECK_CALL(SFileSetMaxFileCount, STORMLIB_NET_CALL(this->m_handle, from_int32(value)) != false);
		}

		AttributeFlag Archive::Attributes::get()
		{
			return static_cast<AttributeFlag>(SFileGetAttributes(this->m_handle));
		}

		void Archive::Attributes::set(AttributeFlag value)
		{
			STORMLIB_NET_FUNC();
			STORMLIB_NET_CHECK_CALL(SFileSetAttributes, STORMLIB_NET_CALL(this->m_handle, static_cast<DWORD>(value)) != false);
		}

		Boolean Archive::IsPatched::get()
		{
			return SFileIsPatchedArchive(this->m_handle);
		}

		String^ Archive::FileName::get()
		{
			if (!this->m_fileName) this->m_fileName = STROMLIB_NET_GET_PROPERTY_TSTRING(SFileMpqFileName);
			return this->m_fileName;
		}

		Int64 Archive::UserDataOffset::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqUserDataOffset);
		}

		array<Byte>^ Archive::UserData::get()
		{
			return STORMLIB_NET_GET_PROPERTY_BYTE_ARRAY(SFileMpqUserData);
		}

		Int64 Archive::HeaderOffset::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqHeaderOffset);
		}

		Int32 Archive::HeaderSize::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileMpqHeaderSize);
		}

		Int64 Archive::HetTableOffset::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqHetTableOffset);
		}

		Int64 Archive::HetTableSize::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqHetTableSize);
		}

		Int64 Archive::BetTableOffset::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqBetTableOffset);
		}

		Int64 Archive::BetTableSize::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqBetTableSize);
		}

		Int64 Archive::HashTableOffset::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqHashTableOffset);
		}

		Int64 Archive::HashTableSize64::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqHashTableSize64);
		}

		Int32 Archive::HashTableSize::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileMpqHashTableSize);
		}

		Int64 Archive::BlockTableOffset::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqBlockTableOffset);
		}

		Int64 Archive::BlockTableSize64::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqBlockTableSize64);
		}

		Int32 Archive::BlockTableSize::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileMpqBlockTableSize);
		}

		Int64 Archive::HiBlockTableOffset::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqHiBlockTableOffset);
		}

		Int64 Archive::HiBlockTableSize64::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqHiBlockTableSize64);
		}

		SignatureType Archive::Signatures::get()
		{
			return STORMLIB_NET_GET_PROPERTY_ENUM(SFileMpqSignatures, SignatureType, 0x03);
		}

		Int64 Archive::StrongSignatureOffset::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqStrongSignatureOffset);
		}

		Int32 Archive::StrongSignatureSize::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileMpqStrongSignatureSize);
		}

		array<Byte>^ Archive::StrongSignature::get()
		{
			return STORMLIB_NET_GET_PROPERTY_BYTE_ARRAY(SFileMpqStrongSignature);
		}

		Int64 Archive::ArchiveSize64::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileMpqArchiveSize64);
		}

		Int32 Archive::ArchiveSize::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileMpqArchiveSize);
		}

		Int32 Archive::FileTableSize::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileMpqFileTableSize);
		}

		Int32 Archive::SectorSize::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileMpqSectorSize);
		}

		Int32 Archive::NumberOfFiles::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileMpqNumberOfFiles);
		}

		Int32 Archive::RawChunkSize::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileMpqRawChunkSize);
		}

		StreamFlag Archive::StreamFlags::get()
		{
			return STORMLIB_NET_GET_PROPERTY_ENUM(SFileMpqStreamFlags, StreamFlag, 0xFF00);
		}

		BaseProvider Archive::BaseProvider::get()
		{
			return STORMLIB_NET_GET_PROPERTY_ENUM(SFileMpqStreamFlags, Net::BaseProvider, 0x000F);
		}

		MpqFlag Archive::Flags::get()
		{
			return STORMLIB_NET_GET_PROPERTY_ENUM(SFileMpqFlags, MpqFlag, 0xFFFF);
		}

		IntPtr Archive::Handle::get()
		{
			return IntPtr(this->m_handle);
		}

		void Archive::Flush()
		{
			STORMLIB_NET_FUNC();
			STORMLIB_NET_CHECK_CALL(SFileFlushArchive, STORMLIB_NET_CALL(this->m_handle) != false);
		}

		void Archive::AddListFile(String^ listFile)
		{
			STORMLIB_NET_FUNC();
			astring_handle listFileH(listFile);
			STORMLIB_NET_CHECK_CALL_INT(SFileAddListFile, STORMLIB_NET_CALL(this->m_handle, listFileH.c_str()));
		}

		void Archive::CompactArchive(String^ listFile)
		{
			STORMLIB_NET_FUNC();
			astring_handle listFileH(listFile);
			compact_callback_wrapper wrapper(this->Context, this->m_handle, this->m_compactCallback);
			STORMLIB_NET_CHECK_CALL(SFileCompactArchive, STORMLIB_NET_CALL(this->m_handle, listFileH.c_str(), false) != false);
			wrapper.done();
		}

		void Archive::UpdateFileAttributes(String^ fileName)
		{
			STORMLIB_NET_FUNC();
			if (!fileName) throw gcnew ArgumentNullException("fileName");
			astring_handle fileNameH(fileName);
			STORMLIB_NET_CHECK_CALL(SFileUpdateFileAttributes, STORMLIB_NET_CALL(this->m_handle, fileNameH.c_str()) != false);
		}

		void Archive::OpenPatchArchive(String^ patchMpqName, String^ patchPrefix)
		{
			STORMLIB_NET_FUNC();
			if (!patchMpqName) throw gcnew ArgumentNullException("patchMpqName");
			if (!patchPrefix) throw gcnew ArgumentNullException("patchPrefix");
			tstring_handle patchMpqNameH(patchMpqName);
			astring_handle patchPrefixH(patchPrefix);
			STORMLIB_NET_CHECK_CALL(SFileOpenPatchArchive, STORMLIB_NET_CALL(this->m_handle, patchMpqNameH.c_str(), patchPrefixH.c_str(), 0) != false);
		}

		Boolean Archive::HasFile(String^ fileName)
		{
			astring_handle fileNameH(fileName);
			return SFileHasFile(this->m_handle, fileNameH.c_str());
		}

		void Archive::ExtractFile(String^ toExtract, String^ extracted)
		{
			STORMLIB_NET_FUNC();
			if (!toExtract) throw gcnew ArgumentNullException("toExtract");
			if (!extracted) throw gcnew ArgumentNullException("extracted");
			astring_handle toExtractH(toExtract);
			tstring_handle extractedH(extracted);
			STORMLIB_NET_CHECK_CALL(SFileExtractFile, STORMLIB_NET_CALL(this->m_handle, toExtractH.c_str(), extractedH.c_str(), SFILE_OPEN_FROM_MPQ) != false);
		}

		VerifyFileResultFlag Archive::VerifyFile(String^ fileName, VerifyFileFlag flags)
		{
			STORMLIB_NET_FUNC();
			if (!fileName) throw gcnew ArgumentNullException("fileName");
			astring_handle fileNameH(fileName);
			DWORD ret;
			STORMLIB_NET_CHECK_CALL(SFileVerifyFile, ((ret = STORMLIB_NET_CALL(this->m_handle, fileNameH.c_str(), static_cast<DWORD>(flags))) & VERIFY_OPEN_ERROR) == 0);
			return static_cast<VerifyFileResultFlag>(ret);
		}

		void Archive::Sign()
		{
			STORMLIB_NET_FUNC();
			STORMLIB_NET_CHECK_CALL(SFileSignArchive, STORMLIB_NET_CALL(this->m_handle, SIGNATURE_TYPE_WEAK) != false);
		}

		VerifyArchiveResult Archive::Verify()
		{
			STORMLIB_NET_FUNC();
			DWORD ret;
			STORMLIB_NET_CHECK_CALL(SFileVerifyArchive, ((ret = STORMLIB_NET_CALL(this->m_handle)) & ERROR_VERIFY_FAILED) == 0);
			return static_cast<VerifyArchiveResult>(ret);
		}

		array<Int32>^ Archive::EnumLocales(String^ fileName)
		{
			STORMLIB_NET_FUNC();
			if (!fileName) throw gcnew ArgumentNullException("fileName");
			astring_handle fileNameH(fileName);
			DWORD maxCnt = 0;
			STORMLIB_NET_CHECK_CALL_INT(SFileEnumLocales, STORMLIB_NET_CALL(this->m_handle, fileNameH.c_str(), NULL, &maxCnt, 0));
			array<Int32>^ ret = gcnew array<Int32>(to_int32(maxCnt));
			if (maxCnt > 0) {
				pin_ptr<Int32> ptr = &ret[0];
				static_assert(sizeof(LCID) == sizeof(Int32), "size mismatch");
				STORMLIB_NET_CHECK_CALL_INT(SFileEnumLocales, STORMLIB_NET_CALL(this->m_handle, fileNameH.c_str(), reinterpret_cast<LCID*>(ptr), &maxCnt, 0));
			}
			return ret;
		}

		void Archive::AddFile(String^ fileName, String^ archivedName, AddFileFlag flags, CompressionFlag compression, CompressionFlag nextCompression)
		{
			STORMLIB_NET_FUNC();
			if (!fileName) throw gcnew ArgumentNullException("fileName");
			if (!archivedName) throw gcnew ArgumentNullException("archivedName");
			tstring_handle fileNameH(fileName);
			astring_handle archivedNameH(archivedName);
			add_file_callback_wrapper wrapper(this->Context, this->m_handle, this->m_addFileCallback);
			STORMLIB_NET_CHECK_CALL(SFileAddFileEx, STORMLIB_NET_CALL(this->m_handle, fileNameH.c_str(), archivedNameH.c_str(), static_cast<DWORD>(flags), static_cast<DWORD>(compression), static_cast<DWORD>(nextCompression)) != false);
			wrapper.done();
		}

		void Archive::AddFile(String^ fileName, String^ archivedName, AddFileFlag flags, CompressionFlag compression)
		{
			this->AddFile(fileName, archivedName, flags, compression, compression);
		}

		void Archive::RemoveFile(String^ fileName)
		{
			STORMLIB_NET_FUNC();
			if (!fileName) throw gcnew ArgumentNullException("fileName");
			astring_handle fileNameH(fileName);
			STORMLIB_NET_CHECK_CALL(SFileRemoveFile, STORMLIB_NET_CALL(this->m_handle, fileNameH.c_str(), 0) != false);
		}

		void Archive::RenameFile(String^ oldFileName, String^ newFileName)
		{
			STORMLIB_NET_FUNC();
			if (!oldFileName) throw gcnew ArgumentNullException("oldFileName");
			if (!newFileName) throw gcnew ArgumentNullException("newFileName");
			astring_handle oldFileNameH(oldFileName);
			astring_handle newFileNameH(newFileName);
			STORMLIB_NET_CHECK_CALL(SFileRenameFile, STORMLIB_NET_CALL(this->m_handle, oldFileNameH.c_str(), newFileNameH.c_str()) != false);
		}

		ExceptionContext^ ArchiveReadFile::Context::get()
		{
			return this->m_archive ? this->m_archive->Context : nullptr;
		}

		ArchiveReadFile::ArchiveReadFile(Net::Archive^ archive, String^ fileName) :
			m_archive(archive),
			m_handle(NULL)
		{
			STORMLIB_NET_FUNC();
			if (!archive) throw gcnew ArgumentNullException("archive");
			if (!fileName) throw gcnew ArgumentNullException("fileName");
			astring_handle fileNameH(fileName);
			pin_ptr<HANDLE> handlePtr = &this->m_handle;
			STORMLIB_NET_CHECK_CALL(SFileOpenFileEx, STORMLIB_NET_CALL(this->m_archive->Handle.ToPointer(), fileNameH.c_str(), SFILE_OPEN_FROM_MPQ, handlePtr) != false);
		}

		ArchiveReadFile::ArchiveReadFile(String^ fileName) :
			m_archive(nullptr),
			m_handle(NULL)
		{
			STORMLIB_NET_FUNC();
			if (!fileName) throw gcnew ArgumentNullException("fileName");
			astring_handle fileNameH(fileName);
			pin_ptr<HANDLE> handlePtr = &this->m_handle;
			STORMLIB_NET_CHECK_CALL(SFileOpenFileEx, STORMLIB_NET_CALL(NULL, fileNameH.c_str(), SFILE_OPEN_LOCAL_FILE, handlePtr) != false);
		}

		ArchiveReadFile::!ArchiveReadFile()
		{
			if (this->m_handle) SFileCloseFile(this->m_handle);
			this->m_handle = NULL;
		}

		ArchiveReadFile::~ArchiveReadFile()
		{
			this->!ArchiveReadFile();
		}

		Net::Archive^ ArchiveReadFile::Archive::get()
		{
			return this->m_archive;
		}

		IntPtr ArchiveReadFile::Handle::get()
		{
			return IntPtr(this->m_handle);
		}

		Int64 ArchiveReadFile::FileSize::get()
		{
			STORMLIB_NET_FUNC();
			ULARGE_INTEGER ul;
			STORMLIB_NET_CHECK_CALL(SFileGetFileSize, (ul.LowPart = STORMLIB_NET_CALL(this->m_handle, &ul.HighPart)) != SFILE_INVALID_SIZE);
			return to_int64(ul.QuadPart);
		}

		Int64 ArchiveReadFile::FilePointer::get()
		{
			return this->Seek(0, SeekOrigin::Current);
		}

		void ArchiveReadFile::FilePointer::set(Int64 value)
		{
			if (value < 0 || value >= this->FileSize) throw gcnew ArgumentOutOfRangeException("value");
			Int64 pos = this->Seek(value, SeekOrigin::Begin);
			if (pos != value) throw gcnew EndOfStreamException();
		}

		Int32 ArchiveReadFile::Locale::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileInfoLocale);
		}

		void ArchiveReadFile::Locale::set(Int32 value)
		{
			STORMLIB_NET_FUNC();
			STORMLIB_NET_CHECK_CALL(SFileSetFileLocale, STORMLIB_NET_CALL(this->m_handle, from_int32(value)) != false);
		}

		String^ ArchiveReadFile::FileName::get()
		{
			if (!this->m_fileName) {
				STORMLIB_NET_FUNC();
				char buffer[MAX_PATH + 1];
				STORMLIB_NET_CHECK_CALL(SFileGetFileName, STORMLIB_NET_CALL(this->m_handle, buffer) != false);
				this->m_fileName = to_string(buffer);
			}
			return this->m_fileName;
		}

		String^ ArchiveReadFile::PatchChain::get()
		{
			if (!this->m_patchChain) this->m_patchChain = STROMLIB_NET_GET_PROPERTY_TSTRING(SFileInfoPatchChain);
			return this->m_patchChain;
		}

		Int32 ArchiveReadFile::HashIndex::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileInfoHashIndex);
		}

		Int32 ArchiveReadFile::NameHash1::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileInfoNameHash1);
		}

		Int32 ArchiveReadFile::NameHash2::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileInfoNameHash2);
		}

		Int64 ArchiveReadFile::NameHash3::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileInfoNameHash3);
		}

		Int32 ArchiveReadFile::FileIndex::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileInfoFileIndex);
		}

		Int64 ArchiveReadFile::ByteOffset::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT64(SFileInfoByteOffset);
		}

		DateTime ArchiveReadFile::FileTime::get()
		{
			return STORMLIB_NET_GET_PROPERTY_DATETIME(SFileInfoFileTime);
		}

		Int32 ArchiveReadFile::CompressedSize::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileInfoCompressedSize);
		}

		FileFlag ArchiveReadFile::Flags::get()
		{
			return STORMLIB_NET_GET_PROPERTY_ENUM(SFileInfoFlags, FileFlag, 0xFFFFFFFF);
		}

		Int32 ArchiveReadFile::EncryptionKey::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileInfoEncryptionKey);
		}

		Int32 ArchiveReadFile::EncryptionKeyRaw::get()
		{
			return STORMLIB_NET_GET_PROPERTY_INT32(SFileInfoEncryptionKeyRaw);
		}

		Boolean ArchiveReadFile::CanRead::get()
		{
			return true;
		}

		Boolean ArchiveReadFile::CanSeek::get()
		{
			return true;
		}

		Boolean ArchiveReadFile::CanWrite::get()
		{
			return false;
		}

		Int64 ArchiveReadFile::Length::get()
		{
			return this->FileSize;
		}

		Int64 ArchiveReadFile::Position::get()
		{
			return this->FilePointer;
		}

		void ArchiveReadFile::Position::set(Int64 value)
		{
			this->FilePointer = value;
		}

		void ArchiveReadFile::Flush()
		{
		}

		Int64 ArchiveReadFile::Seek(Int64 offset, SeekOrigin origin)
		{
			STORMLIB_NET_FUNC();
			DWORD method;
			switch (origin) {
			case SeekOrigin::Begin: method = static_cast<DWORD>(stormlib::seek_method::begin); break;
			case SeekOrigin::Current: method = static_cast<DWORD>(stormlib::seek_method::current); break;
			case SeekOrigin::End: method = static_cast<DWORD>(stormlib::seek_method::end); break;
			default: throw gcnew ArgumentOutOfRangeException("origin");
			}
			LARGE_INTEGER li;
			li.QuadPart = offset;
			STORMLIB_NET_CHECK_CALL(SFileSetFilePointer, (li.LowPart = STORMLIB_NET_CALL(this->m_handle, li.LowPart, &li.HighPart, method)) != SFILE_INVALID_POS);
			return li.QuadPart;
		}

		void ArchiveReadFile::SetLength(Int64 value)
		{
			(void)value;
			throw gcnew NotSupportedException("SetLength");
		}

		Int32 ArchiveReadFile::Read(array<Byte>^ buffer, Int32 offset, Int32 count)
		{
			STORMLIB_NET_FUNC();
			if (!buffer) throw gcnew ArgumentNullException("buffer");
			if (offset < 0 || offset >= buffer->Length) throw gcnew ArgumentOutOfRangeException("offset");
			if (count < 0 || offset + count > buffer->Length) throw gcnew ArgumentOutOfRangeException("count");
			pin_ptr<Byte> ptr = &buffer[0];
			DWORD read;
			STORMLIB_NET_CHECK_CALL(SFileReadFile, STORMLIB_NET_CALL(this->m_handle, ptr + offset, count, &read, nullptr) != false, ERROR_HANDLE_EOF);
			return to_int32(read);
		}

		void ArchiveReadFile::Write(array<Byte>^ buffer, Int32 offset, Int32 count)
		{
			(void)buffer;
			(void)offset;
			(void)count;
			throw gcnew NotSupportedException("Write");
		}

		ExceptionContext^ ArchiveWriteFile::Context::get()
		{
			return this->m_archive->Context;
		}

		ArchiveWriteFile::ArchiveWriteFile(Net::Archive^ archive, String^ fileName, DateTime fileTime, Int32 fileSize, Int32 locale, AddFileFlag flags) :
			m_archive(archive),
			m_fileName(fileName),
			m_fileTime(fileTime),
			m_filePointer(0),
			m_fileSize(fileSize),
			m_locale(locale),
			m_handle(nullptr),
			m_compression(CompressionFlag::None)
		{
			STORMLIB_NET_FUNC();
			if (!archive) throw gcnew ArgumentNullException("archive");
			if (!fileName) throw gcnew ArgumentNullException("fileName");
			astring_handle fileNameH(fileName);
			pin_ptr<HANDLE> handlePtr = &this->m_handle;
			STORMLIB_NET_CHECK_CALL(SFileCreateFile, STORMLIB_NET_CALL(this->m_archive->Handle.ToPointer(), fileNameH.c_str(), from_datetime(fileTime), from_int32(fileSize), from_int32(locale), static_cast<DWORD>(flags), handlePtr) != false);
		}

		ArchiveWriteFile::!ArchiveWriteFile()
		{
			if (this->m_handle != NULL) SFileFinishFile(this->m_handle);
			this->m_handle = NULL;
		}

		ArchiveWriteFile::~ArchiveWriteFile()
		{
			this->!ArchiveWriteFile();
		}

		Net::Archive^ ArchiveWriteFile::Archive::get()
		{
			return this->m_archive;
		}

		IntPtr ArchiveWriteFile::Handle::get()
		{
			return IntPtr(this->m_handle);
		}

		Int32 ArchiveWriteFile::FileSize::get()
		{
			return this->m_fileSize;
		}

		Int32 ArchiveWriteFile::FilePointer::get()
		{
			return this->m_filePointer;
		}

		Int32 ArchiveWriteFile::Locale::get()
		{
			return this->m_locale;
		}

		String^ ArchiveWriteFile::FileName::get()
		{
			return this->m_fileName;
		}

		CompressionFlag ArchiveWriteFile::Compression::get()
		{
			return this->m_compression;
		}

		void ArchiveWriteFile::Compression::set(CompressionFlag value)
		{
			this->m_compression = value;
		}

		Boolean ArchiveWriteFile::CanRead::get()
		{
			return false;
		}

		Boolean ArchiveWriteFile::CanSeek::get()
		{
			return false;
		}

		Boolean ArchiveWriteFile::CanWrite::get()
		{
			return true;
		}

		Int64 ArchiveWriteFile::Length::get()
		{
			return this->FileSize;
		}

		Int64 ArchiveWriteFile::Position::get()
		{
			return this->FilePointer;
		}

		void ArchiveWriteFile::Position::set(Int64 value)
		{
			(void)value;
			throw gcnew NotSupportedException("Position::set");
		}

		void ArchiveWriteFile::Flush()
		{
			STORMLIB_NET_FUNC();
			STORMLIB_NET_CHECK_CALL(SFileFinishFile, STORMLIB_NET_CALL(this->m_handle) != false);
			this->m_handle = NULL;
		}

		Int64 ArchiveWriteFile::Seek(Int64 offset, SeekOrigin origin)
		{
			(void)offset;
			(void)origin;
			throw gcnew NotSupportedException("Seek");
		}

		void ArchiveWriteFile::SetLength(Int64 value)
		{
			(void)value;
			throw gcnew NotSupportedException("SetLength");
		}

		Int32 ArchiveWriteFile::Read(array<Byte> ^buffer, Int32 offset, Int32 count)
		{
			(void)buffer;
			(void)offset;
			(void)count;
			throw gcnew NotSupportedException("Read");
		}

		void ArchiveWriteFile::Write(array<Byte> ^buffer, Int32 offset, Int32 count)
		{
			STORMLIB_NET_FUNC();
			if (!buffer) throw gcnew ArgumentNullException("buffer");
			if (offset < 0 || offset >= buffer->Length) throw gcnew ArgumentOutOfRangeException("offset");
			if (count < 0 || offset + count > buffer->Length) throw gcnew ArgumentOutOfRangeException("count");
			pin_ptr<Byte> ptr = &buffer[0];
			STORMLIB_NET_CHECK_CALL(SFileWriteFile, STORMLIB_NET_CALL(this->m_handle, ptr + offset, count, static_cast<DWORD>(this->m_compression)) != false);
			this->m_filePointer += count;
		}

		ExceptionContext^ ArchiveEnumerator::Context::get()
		{
			return this->m_archive->Context;
		}

		ArchiveEnumerator::ArchiveEnumerator(Net::Archive^ archive, String^ mask, String^ listFile) :
			m_handle(NULL),
			m_findData(nullptr),
			m_archive(archive)
		{
			if (!archive) throw gcnew ArgumentNullException("archive");
			if (!mask) throw gcnew ArgumentNullException("mask");
			STORMLIB_NET_FUNC();
			astring_handle maskH(mask);
			astring_handle listFileH(listFile);
			this->m_findData = new SFILE_FIND_DATA();
			memset(this->m_findData, 0, sizeof(SFILE_FIND_DATA));
			DWORD error;
			STORMLIB_NET_CHECK_CALL_EX(error, SFileFindFirstFile, (this->m_handle = STORMLIB_NET_CALL(this->m_archive->Handle.ToPointer(), maskH.c_str(), this->m_findData, listFileH.c_str())) != NULL, ERROR_NO_MORE_FILES);
			if (error == ERROR_NO_MORE_FILES) {
				if (this->m_handle != NULL) SFileFindClose(this->m_handle);
				this->m_handle = NULL;
				if (this->m_findData) delete this->m_findData;
				this->m_findData = nullptr;
			}
		}

		ArchiveEnumerator::ArchiveEnumerator(Net::Archive^ archive, String^ listFile) :
			m_handle(NULL),
			m_findData(nullptr),
			m_archive(archive)
		{
			if (!archive) throw gcnew ArgumentNullException("archive");
			STORMLIB_NET_FUNC();
			astring_handle listFileH(listFile);
			this->m_findData = new SFILE_FIND_DATA();
			memset(this->m_findData, 0, sizeof(SFILE_FIND_DATA));
			DWORD error;
			STORMLIB_NET_CHECK_CALL_EX(error, SFileFindFirstFile, (this->m_handle = STORMLIB_NET_CALL(this->m_archive->Handle.ToPointer(), "*", this->m_findData, listFileH.c_str())) != NULL, ERROR_NO_MORE_FILES);
			if (error == ERROR_NO_MORE_FILES) {
				if (this->m_handle != NULL) SFileFindClose(this->m_handle);
				this->m_handle = NULL;
				if (this->m_findData) delete this->m_findData;
				this->m_findData = nullptr;
			}
		}

		ArchiveEnumerator::ArchiveEnumerator(Net::Archive^ archive) :
			m_handle(NULL),
			m_findData(nullptr),
			m_archive(archive)
		{
			if (!archive) throw gcnew ArgumentNullException("archive");
			STORMLIB_NET_FUNC();
			this->m_findData = new SFILE_FIND_DATA();
			memset(this->m_findData, 0, sizeof(SFILE_FIND_DATA));
			DWORD error;
			STORMLIB_NET_CHECK_CALL_EX(error, SFileFindFirstFile, (this->m_handle = STORMLIB_NET_CALL(this->m_archive->Handle.ToPointer(), "*", this->m_findData, nullptr)) != NULL, ERROR_NO_MORE_FILES);
			if (error == ERROR_NO_MORE_FILES) {
				if (this->m_handle != NULL) SFileFindClose(this->m_handle);
				this->m_handle = NULL;
				if (this->m_findData) delete this->m_findData;
				this->m_findData = nullptr;
			}
		}

		ArchiveEnumerator::!ArchiveEnumerator()
		{
			if (this->m_handle != NULL) SFileFindClose(this->m_handle);
			this->m_handle = NULL;
			if (this->m_findData) delete this->m_findData;
			this->m_findData = nullptr;
		}

		ArchiveEnumerator::~ArchiveEnumerator()
		{
			this->!ArchiveEnumerator();
		}

		Net::Archive^ ArchiveEnumerator::Archive::get()
		{
			return this->m_archive;
		}

		IntPtr ArchiveEnumerator::Handle::get()
		{
			return IntPtr(this->m_handle);
		}

		Boolean ArchiveEnumerator::IsValid::get()
		{
			return this->m_findData != nullptr;
		}

		String^ ArchiveEnumerator::FileName::get()
		{
			if (!this->m_findData) return nullptr;
			if (!this->m_fileName) this->m_fileName = to_string(this->m_findData->cFileName);
			return this->m_fileName;
		}

		String^ ArchiveEnumerator::PlainName::get()
		{
			if (!this->m_findData) return nullptr;
			if (!this->m_plainName) this->m_plainName = to_string(this->m_findData->szPlainName);
			return this->m_plainName;
		}

		Int32 ArchiveEnumerator::HashIndex::get()
		{
			return this->m_findData ? to_int32(this->m_findData->dwHashIndex) : 0;
		}

		Int32 ArchiveEnumerator::BlockIndex::get()
		{
			return this->m_findData ? to_int32(this->m_findData->dwBlockIndex) : 0;
		}

		Int32 ArchiveEnumerator::FileSize::get()
		{
			return this->m_findData ? to_int32(this->m_findData->dwFileSize) : 0;
		}

		FileFlag ArchiveEnumerator::Flags::get()
		{
			return this->m_findData ? static_cast<FileFlag>(this->m_findData->dwFileFlags) : FileFlag::None;
		}

		Int32 ArchiveEnumerator::CompressedSize::get()
		{
			return this->m_findData ? to_int32(this->m_findData->dwCompSize) : 0;
		}

		DateTime ArchiveEnumerator::FileTime::get()
		{
			if (!this->m_findData) return DateTime();
			ULARGE_INTEGER ul;
			ul.LowPart = this->m_findData->dwFileTimeLo;
			ul.HighPart = this->m_findData->dwFileTimeHi;
			return to_datetime(ul.QuadPart);
		}

		Int32 ArchiveEnumerator::Locale::get()
		{
			return this->m_findData ? to_int32(this->m_findData->lcLocale) : Constants::LanguageNeutral;
		}

		void ArchiveEnumerator::Next()
		{
			STORMLIB_NET_FUNC();
			this->m_fileName = nullptr;
			this->m_plainName = nullptr;
			if (this->m_findData) {
				DWORD error;
				STORMLIB_NET_CHECK_CALL_EX(error, SFileFindNextFile, STORMLIB_NET_CALL(this->m_handle, this->m_findData) != false, ERROR_NO_MORE_FILES);
				if (error == ERROR_NO_MORE_FILES) {
					if (this->m_handle != NULL) SFileFindClose(this->m_handle);
					this->m_handle = NULL;
					if (this->m_findData) delete this->m_findData;
					this->m_findData = nullptr;
				}
			}
		}

		ExceptionContext^ ListfileEnumerator::Context::get()
		{
			return this->m_archive->Context;
		}

		ListfileEnumerator::ListfileEnumerator(Net::Archive^ archive, String^ mask, String^ listFile) :
			m_handle(NULL),
			m_findData(nullptr),
			m_archive(archive)
		{
			if (!archive) throw gcnew ArgumentNullException("archive");
			if (!mask) throw gcnew ArgumentNullException("mask");
			STORMLIB_NET_FUNC();
			astring_handle maskH(mask);
			astring_handle listFileH(listFile);
			this->m_findData = new SFILE_FIND_DATA();
			memset(this->m_findData, 0, sizeof(SFILE_FIND_DATA));
			DWORD error;
			STORMLIB_NET_CHECK_CALL_EX(error, SListFileFindFirstFile, (this->m_handle = STORMLIB_NET_CALL(this->m_archive->Handle.ToPointer(), listFileH.c_str(), maskH.c_str(), this->m_findData)) != NULL, ERROR_NO_MORE_FILES);
			if (error == ERROR_NO_MORE_FILES) {
				if (this->m_handle != NULL) SListFileFindClose(this->m_handle);
				this->m_handle = NULL;
				if (this->m_findData) delete this->m_findData;
				this->m_findData = nullptr;
			}
		}

		ListfileEnumerator::ListfileEnumerator(Net::Archive^ archive, String^ listFile) :
			m_handle(NULL),
			m_findData(nullptr),
			m_archive(archive)
		{
			if (!archive) throw gcnew ArgumentNullException("archive");
			STORMLIB_NET_FUNC();
			astring_handle listFileH(listFile);
			this->m_findData = new SFILE_FIND_DATA();
			memset(this->m_findData, 0, sizeof(SFILE_FIND_DATA));
			DWORD error;
			STORMLIB_NET_CHECK_CALL_EX(error, SListFileFindFirstFile, (this->m_handle = STORMLIB_NET_CALL(this->m_archive->Handle.ToPointer(), listFileH.c_str(), "*", this->m_findData)) != NULL, ERROR_NO_MORE_FILES);
			if (error == ERROR_NO_MORE_FILES) {
				if (this->m_handle != NULL) SListFileFindClose(this->m_handle);
				this->m_handle = NULL;
				if (this->m_findData) delete this->m_findData;
				this->m_findData = nullptr;
			}
		}

		ListfileEnumerator::ListfileEnumerator(Net::Archive^ archive) :
			m_handle(NULL),
			m_findData(nullptr),
			m_archive(archive)
		{
			if (!archive) throw gcnew ArgumentNullException("archive");
			STORMLIB_NET_FUNC();
			this->m_findData = new SFILE_FIND_DATA();
			memset(this->m_findData, 0, sizeof(SFILE_FIND_DATA));
			DWORD error;
			STORMLIB_NET_CHECK_CALL_EX(error, SListFileFindFirstFile, (this->m_handle = STORMLIB_NET_CALL(this->m_archive->Handle.ToPointer(), nullptr, "*", this->m_findData)) != NULL, ERROR_NO_MORE_FILES);
			if (error == ERROR_NO_MORE_FILES) {
				if (this->m_handle != NULL) SListFileFindClose(this->m_handle);
				this->m_handle = NULL;
				if (this->m_findData) delete this->m_findData;
				this->m_findData = nullptr;
			}
		}

		ListfileEnumerator::!ListfileEnumerator()
		{
			if (this->m_handle != NULL) SListFileFindClose(this->m_handle);
			this->m_handle = NULL;
			if (this->m_findData) delete this->m_findData;
			this->m_findData = nullptr;
		}

		ListfileEnumerator::~ListfileEnumerator()
		{
			this->!ListfileEnumerator();
		}

		Net::Archive^ ListfileEnumerator::Archive::get()
		{
			return this->m_archive;
		}

		IntPtr ListfileEnumerator::Handle::get()
		{
			return IntPtr(this->m_handle);
		}

		Boolean ListfileEnumerator::IsValid::get()
		{
			return this->m_findData != nullptr;
		}

		String^ ListfileEnumerator::FileName::get()
		{
			if (!this->m_findData) return nullptr;
			if (!this->m_fileName) this->m_fileName = to_string(this->m_findData->cFileName);
			return this->m_fileName;
		}

		String^ ListfileEnumerator::PlainName::get()
		{
			if (!this->m_findData) return nullptr;
			if (!this->m_plainName) this->m_plainName = to_string(this->m_findData->szPlainName);
			return this->m_plainName;
		}

		Int32 ListfileEnumerator::HashIndex::get()
		{
			return this->m_findData ? to_int32(this->m_findData->dwHashIndex) : 0;
		}

		Int32 ListfileEnumerator::BlockIndex::get()
		{
			return this->m_findData ? to_int32(this->m_findData->dwBlockIndex) : 0;
		}

		Int32 ListfileEnumerator::FileSize::get()
		{
			return this->m_findData ? to_int32(this->m_findData->dwFileSize) : 0;
		}

		FileFlag ListfileEnumerator::Flags::get()
		{
			return this->m_findData ? static_cast<FileFlag>(this->m_findData->dwFileFlags) : FileFlag::None;
		}

		Int32 ListfileEnumerator::CompressedSize::get()
		{
			return this->m_findData ? to_int32(this->m_findData->dwCompSize) : 0;
		}

		DateTime ListfileEnumerator::FileTime::get()
		{
			if (!this->m_findData) return DateTime();
			ULARGE_INTEGER ul;
			ul.LowPart = this->m_findData->dwFileTimeLo;
			ul.HighPart = this->m_findData->dwFileTimeHi;
			return to_datetime(ul.QuadPart);
		}

		Int32 ListfileEnumerator::Locale::get()
		{
			return this->m_findData ? to_int32(this->m_findData->lcLocale) : Constants::LanguageNeutral;
		}

		void ListfileEnumerator::Next()
		{
			STORMLIB_NET_FUNC();
			this->m_fileName = nullptr;
			this->m_plainName = nullptr;
			if (this->m_findData) {
				DWORD error;
				STORMLIB_NET_CHECK_CALL_EX(error, SListFileFindNextFile, STORMLIB_NET_CALL(this->m_handle, this->m_findData) != false, ERROR_NO_MORE_FILES);
				if (error == ERROR_NO_MORE_FILES) {
					if (this->m_handle != NULL) SListFileFindClose(this->m_handle);
					this->m_handle = NULL;
					if (this->m_findData) delete this->m_findData;
					this->m_findData = nullptr;
				}
			}
		}

		ArchiveFileInfo::ArchiveFileInfo(IArchiveEnumerator^ enumerator)
		{
			if (!enumerator) throw gcnew ArgumentNullException("enumerator");
			if (!enumerator->IsValid) throw gcnew ArgumentException("enumerator not valid", "enumerator");
			this->m_archive = enumerator->Archive;
			this->m_fileName = enumerator->FileName;
			this->m_plainName = enumerator->PlainName;
			this->m_hashIndex = enumerator->HashIndex;
			this->m_blockIndex = enumerator->BlockIndex;
			this->m_fileSize = enumerator->FileSize;
			this->m_flags = enumerator->Flags;
			this->m_compressedSize = enumerator->CompressedSize;
			this->m_fileTime = enumerator->FileTime;
			this->m_locale = enumerator->Locale;
		}

		Archive^ ArchiveFileInfo::Archive::get()
		{
			return this->m_archive;
		}

		String^ ArchiveFileInfo::FileName::get()
		{
			return this->m_fileName;
		}

		String^ ArchiveFileInfo::PlainName::get()
		{
			return this->m_plainName;
		}

		Int32 ArchiveFileInfo::HashIndex::get()
		{
			return this->m_hashIndex;
		}

		Int32 ArchiveFileInfo::BlockIndex::get()
		{
			return this->m_blockIndex;
		}

		Int32 ArchiveFileInfo::FileSize::get()
		{
			return this->m_fileSize;
		}

		FileFlag ArchiveFileInfo::Flags::get()
		{
			return this->m_flags;
		}

		Int32 ArchiveFileInfo::CompressedSize::get()
		{
			return this->m_compressedSize;
		}

		DateTime ArchiveFileInfo::FileTime::get()
		{
			return this->m_fileTime;
		}

		Int32 ArchiveFileInfo::Locale::get()
		{
			return this->m_locale;
		}

		ref class ArchiveFileCollection::Enumerator sealed : public Generic::IEnumerator<ArchiveFileInfo^>, public IEnumerator
		{
		private:
			ArchiveFileCollection^ m_collection;
			Int32 m_index;

		public:
			Enumerator(ArchiveFileCollection^ collection)
			{
				if (!collection) throw gcnew ArgumentNullException("collection");
				this->m_collection = collection;
				this->m_index = -1;
			}

			~Enumerator()
			{
			}

			virtual bool MoveNext()
			{
				++this->m_index;
				return this->m_collection->UpdateNext(this->m_index);
			}

			property ArchiveFileInfo^ Current
			{
				virtual ArchiveFileInfo^ get()
				{
					return this->m_collection->Get(this->m_index);
				}
			};

			property Object^ Current2
			{
				virtual Object^ get() = IEnumerator::Current::get
				{
					return this->Current;
				}
			};

			virtual void Reset()
			{
				this->m_index = -1;
			}
		};

		Boolean ArchiveFileCollection::UpdateNext(Int32 index)
		{
			while (index >= this->m_info->Count) {
				if (!this->m_enumerator->IsValid) return false;
				this->m_info->Add(gcnew ArchiveFileInfo(this->m_enumerator));
				this->m_enumerator->Next();
			}
			return true;
		}

		ArchiveFileInfo^ ArchiveFileCollection::Get(Int32 index)
		{
			return this->m_info[index];
		}

		ArchiveFileCollection::ArchiveFileCollection(Net::Archive^ archive, ArchiveEnumerationType type)
		{
			if (!archive) throw gcnew ArgumentNullException("archive");
			switch (type) {
			case ArchiveEnumerationType::Archive: this->m_enumerator = gcnew ArchiveEnumerator(archive); break;
			case ArchiveEnumerationType::Listfile: this->m_enumerator = gcnew ListfileEnumerator(archive); break;
			default: throw gcnew ArgumentOutOfRangeException("type");
			}
			this->m_info = gcnew Generic::List<ArchiveFileInfo^>();
		}

		ArchiveFileCollection::ArchiveFileCollection(Net::Archive^ archive, String^ listFile, ArchiveEnumerationType type)
		{
			if (!archive) throw gcnew ArgumentNullException("archive");
			if (!listFile) throw gcnew ArgumentNullException("listFile");
			switch (type) {
			case ArchiveEnumerationType::Archive: this->m_enumerator = gcnew ArchiveEnumerator(archive, listFile); break;
			case ArchiveEnumerationType::Listfile: this->m_enumerator = gcnew ListfileEnumerator(archive, listFile); break;
			default: throw gcnew ArgumentOutOfRangeException("type");
			}
			this->m_info = gcnew Generic::List<ArchiveFileInfo^>();
		}

		ArchiveFileCollection::ArchiveFileCollection(Net::Archive^ archive, String^ mask, String^ listFile, ArchiveEnumerationType type)
		{
			if (!archive) throw gcnew ArgumentNullException("archive");
			if (!mask) throw gcnew ArgumentNullException("mask");
			if (!listFile) throw gcnew ArgumentNullException("listFile");
			switch (type) {
			case ArchiveEnumerationType::Archive: this->m_enumerator = gcnew ArchiveEnumerator(archive, mask, listFile); break;
			case ArchiveEnumerationType::Listfile: this->m_enumerator = gcnew ListfileEnumerator(archive, mask, listFile); break;
			default: throw gcnew ArgumentOutOfRangeException("type");
			}
			this->m_info = gcnew Generic::List<ArchiveFileInfo^>();
		}

		ArchiveFileCollection::ArchiveFileCollection(IArchiveEnumerator^ enumerator)
		{
			if (!enumerator) throw gcnew ArgumentNullException("enumerator");
			this->m_enumerator = enumerator;
			this->m_info = gcnew Generic::List<ArchiveFileInfo^>();
		}

		ArchiveFileCollection::~ArchiveFileCollection()
		{
			delete this->m_enumerator;
		}

		Net::Archive^ ArchiveFileCollection::Archive::get()
		{
			return this->m_enumerator->Archive;
		}

		Generic::IEnumerator<ArchiveFileInfo^>^ ArchiveFileCollection::GetEnumerator()
		{
			return gcnew Enumerator(this);
		}

		IEnumerator^ ArchiveFileCollection::EnumerableGetEnumerator()
		{
			return this->GetEnumerator();
		}

		AviFileException::AviFileException()
		{
		}

		AviFileException::AviFileException(String^ message) :
			IOException(message)
		{
		}

		AviFileException::AviFileException(String^ message, Exception^ inner) :
			IOException(message, inner)
		{
		}

		AviFileException::AviFileException(SerializationInfo^ info, StreamingContext context) :
			IOException(info, context)
		{
		}

		UnknownFileKeyException::UnknownFileKeyException()
		{
		}

		UnknownFileKeyException::UnknownFileKeyException(String^ message) :
			IOException(message)
		{
		}

		UnknownFileKeyException::UnknownFileKeyException(String^ message, Exception^ inner) :
			IOException(message, inner)
		{
		}

		UnknownFileKeyException::UnknownFileKeyException(SerializationInfo^ info, StreamingContext context) :
			IOException(info, context)
		{
		}

		ChecksumErrorException::ChecksumErrorException()
		{
		}

		ChecksumErrorException::ChecksumErrorException(String^ message) :
			IOException(message)
		{
		}

		ChecksumErrorException::ChecksumErrorException(String^ message, Exception^ inner) :
			IOException(message, inner)
		{
		}

		ChecksumErrorException::ChecksumErrorException(SerializationInfo^ info, StreamingContext context) :
			IOException(info, context)
		{
		}

		InternalFileException::InternalFileException()
		{
		}

		InternalFileException::InternalFileException(String^ message) :
			IOException(message)
		{
		}

		InternalFileException::InternalFileException(String^ message, Exception^ inner) :
			IOException(message, inner)
		{
		}

		InternalFileException::InternalFileException(SerializationInfo^ info, StreamingContext context) :
			IOException(info, context)
		{
		}

		BaseFileMissingException::BaseFileMissingException()
		{
		}

		BaseFileMissingException::BaseFileMissingException(String^ message) :
			IOException(message)
		{
		}

		BaseFileMissingException::BaseFileMissingException(String^ message, Exception^ inner) :
			IOException(message, inner)
		{
		}

		BaseFileMissingException::BaseFileMissingException(SerializationInfo^ info, StreamingContext context) :
			IOException(info, context)
		{
		}

		MarkedForDeleteException::MarkedForDeleteException()
		{
		}

		MarkedForDeleteException::MarkedForDeleteException(String^ message) :
			IOException(message)
		{
		}

		MarkedForDeleteException::MarkedForDeleteException(String^ message, Exception^ inner) :
			IOException(message, inner)
		{
		}

		MarkedForDeleteException::MarkedForDeleteException(SerializationInfo^ info, StreamingContext context) :
			IOException(info, context)
		{
		}

		FileIncompleteException::FileIncompleteException()
		{
		}

		FileIncompleteException::FileIncompleteException(String^ message) :
			IOException(message)
		{
		}

		FileIncompleteException::FileIncompleteException(String^ message, Exception^ inner) :
			IOException(message, inner)
		{
		}

		FileIncompleteException::FileIncompleteException(SerializationInfo^ info, StreamingContext context) :
			IOException(info, context)
		{
		}

		UnknownFileNamesException::UnknownFileNamesException()
		{
		}

		UnknownFileNamesException::UnknownFileNamesException(String^ message) :
			IOException(message)
		{
		}

		UnknownFileNamesException::UnknownFileNamesException(String^ message, Exception^ inner) :
			IOException(message, inner)
		{
		}

		UnknownFileNamesException::UnknownFileNamesException(SerializationInfo^ info, StreamingContext context) :
			IOException(info, context)
		{
		}

		CantFindPatchPrefixException::CantFindPatchPrefixException()
		{
		}

		CantFindPatchPrefixException::CantFindPatchPrefixException(String^ message) :
			IOException(message)
		{
		}

		CantFindPatchPrefixException::CantFindPatchPrefixException(String^ message, Exception^ inner) :
			IOException(message, inner)
		{
		}

		CantFindPatchPrefixException::CantFindPatchPrefixException(SerializationInfo^ info, StreamingContext context) :
			IOException(info, context)
		{
		}

		ExceptionLostException::ExceptionLostException()
		{
		}

		ExceptionLostException::ExceptionLostException(String^ message) :
			Exception(message)
		{
		}

		ExceptionLostException::ExceptionLostException(String^ message, Exception^ inner) :
			Exception(message, inner)
		{
		}

		ExceptionLostException::ExceptionLostException(SerializationInfo^ info, StreamingContext context) :
			Exception(info, context)
		{
		}
	}
}

