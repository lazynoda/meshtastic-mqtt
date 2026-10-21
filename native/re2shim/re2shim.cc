// A thin C API over Google RE2 for the packet filters of the broker, called with P/Invoke from .NET
// (src/Meshtastic.Mqtt/Re2.cs).
//
// It does only what the filters need: compile a pattern with fixed options and a memory budget, read
// the error of a pattern that does not compile, an unanchored match without captures, and free.
// It is built against the RE2 of the distribution of the image (libre2-dev), see the Dockerfile and
// build.sh. No C++ exception crosses into .NET: an exception that crossed would abort the process.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <string>

#include <re2/re2.h>

#define RE2SHIM_API extern "C" __attribute__((visibility("default")))

// The version of this API. The managed side checks it, so a stale library is refused at once.
RE2SHIM_API int32_t re2shim_abi_version() { return 1; }

// Compiles a UTF-8 pattern. Returns null only when there is no memory to build the object; a pattern
// that RE2 refuses still returns an object, whose error re2shim_error_code and re2shim_error read.
// max_mem bounds the memory of the compiled program and of the caches RE2 builds while it matches:
// when a cache fills its share, RE2 flushes it and starts over.
RE2SHIM_API re2::RE2* re2shim_compile(const char* pattern, size_t length, int64_t max_mem) {
    try {
        RE2::Options options;
        options.set_encoding(RE2::Options::EncodingUTF8);
        options.set_log_errors(false);
        options.set_longest_match(false);
        options.set_max_mem(max_mem);
        return new re2::RE2(re2::StringPiece(pattern, length), options);
    } catch (...) {
        return nullptr;
    }
}

// 0 when the pattern compiled, otherwise the RE2::ErrorCode of the failure.
RE2SHIM_API int32_t re2shim_error_code(const re2::RE2* re) { return static_cast<int32_t>(re->error_code()); }

// Copies the error text of the pattern (UTF-8, not terminated) into buffer, at most capacity bytes,
// and returns its full length.
RE2SHIM_API size_t re2shim_error(const re2::RE2* re, char* buffer, size_t capacity) {
    const std::string& error = re->error();
    size_t n = error.size() < capacity ? error.size() : capacity;
    if (n > 0)
        std::memcpy(buffer, error.data(), n);
    return error.size();
}

// 1 when the pattern matches anywhere in the UTF-8 text, 0 when it does not, -1 when RE2 failed (no
// memory). Matching is a const operation of RE2, which is safe to run from many threads at once on
// the same object: RE2 guards the caches it builds lazily with its own locks.
RE2SHIM_API int32_t re2shim_partial_match(const re2::RE2* re, const char* text, size_t length) {
    try {
        return RE2::PartialMatch(re2::StringPiece(text, length), *re) ? 1 : 0;
    } catch (...) {
        return -1;
    }
}

RE2SHIM_API void re2shim_free(re2::RE2* re) { delete re; }
