#include "protocol.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <initializer_list>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>

namespace ft {
namespace {

using View = std::span<const std::uint8_t>;

void
check(NTSTATUS status, const char *operation)
{
    if (status < 0)
    {
        throw std::runtime_error(
            std::string(operation) + " failed (CNG status " + std::to_string(static_cast<std::uint32_t>(status)) + ")");
    }
}

ULONG
length(std::size_t size)
{
    if (size > std::numeric_limits<ULONG>::max())
    {
        throw std::runtime_error("cryptographic input exceeds CNG size limit");
    }
    return static_cast<ULONG>(size);
}

PUCHAR
mutable_bytes(View bytes)
{
    return const_cast<PUCHAR>(bytes.data());
}

View
bytes(std::string_view text)
{
    return { reinterpret_cast<const std::uint8_t *>(text.data()), text.size() };
}

class Algorithm
{
public:
    BCRYPT_ALG_HANDLE handle{};
    explicit Algorithm(LPCWSTR name, ULONG flags = 0)
    {
        check(BCryptOpenAlgorithmProvider(&handle, name, nullptr, flags), "open cryptographic provider");
    }
    ~Algorithm() { BCryptCloseAlgorithmProvider(handle, 0); }
    Algorithm(const Algorithm &) = delete;
    Algorithm &operator=(const Algorithm &) = delete;
};

ULONG
object_size(BCRYPT_ALG_HANDLE handle)
{
    ULONG value{}, written{};
    check(
        BCryptGetProperty(handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&value), sizeof(value), &written, 0),
        "query cryptographic object size");
    return value;
}

class HashHandle
{
public:
    BCRYPT_HASH_HANDLE handle{};
    ~HashHandle()
    {
        if (handle)
            BCryptDestroyHash(handle);
    }
};

Bytes
hash(bool keyed, View key, std::initializer_list<View> parts)
{
    Algorithm algorithm(BCRYPT_SHA256_ALGORITHM, keyed ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
    Bytes object(object_size(algorithm.handle));
    HashHandle state;
    check(
        BCryptCreateHash(
            algorithm.handle,
            &state.handle,
            object.data(),
            length(object.size()),
            mutable_bytes(key),
            length(key.size()),
            0),
        "create SHA-256 state");
    for (auto part : parts)
    {
        if (!part.empty())
        {
            check(BCryptHashData(state.handle, mutable_bytes(part), length(part.size()), 0), "hash data");
        }
    }
    Bytes output(32);
    check(BCryptFinishHash(state.handle, output.data(), length(output.size()), 0), "finish SHA-256");
    return output;
}

Bytes
authenticate(const Key &key, std::string_view domain, View first, View second = {})
{
    const std::array<std::uint8_t, 1> zero{};
    return hash(true, key, { bytes(domain), zero, first, second });
}

bool
constant_equal(View left, View right)
{
    if (left.size() != right.size())
        return false;
    volatile std::uint8_t difference = 0;
    for (std::size_t i = 0; i < left.size(); ++i)
    {
        difference = static_cast<std::uint8_t>(difference | (left[i] ^ right[i]));
    }
    return difference == 0;
}

std::uint64_t
load64(View data)
{
    std::uint64_t value{};
    for (std::size_t i = 0; i < 8; ++i)
        value = (value << 8) | data[i];
    return value;
}

void
store64(std::uint8_t *data, std::uint64_t value)
{
    for (int i = 7; i >= 0; --i)
    {
        data[i] = static_cast<std::uint8_t>(value);
        value >>= 8;
    }
}

Bytes
derive_material(const Key &key, View salt, std::string_view label)
{
    auto extracted = hash(true, salt, { key });
    const std::array<std::uint8_t, 1> counter{ 1 };
    auto expanded = hash(true, extracted, { bytes(label), counter });
    SecureZeroMemory(extracted.data(), extracted.size());
    expanded.resize(20);
    return expanded;
}

class SymmetricKey
{
public:
    BCRYPT_KEY_HANDLE handle{};
    ~SymmetricKey()
    {
        if (handle)
            BCryptDestroyKey(handle);
    }
};

struct Direction
{
    Algorithm algorithm{ BCRYPT_AES_ALGORITHM };
    Bytes object;
    SymmetricKey key;
    std::array<std::uint8_t, 4> prefix{};

    explicit Direction(View material)
    {
        check(
            BCryptSetProperty(
                algorithm.handle,
                BCRYPT_CHAINING_MODE,
                reinterpret_cast<PUCHAR>(const_cast<wchar_t *>(BCRYPT_CHAIN_MODE_GCM)),
                sizeof(BCRYPT_CHAIN_MODE_GCM),
                0),
            "select AES-GCM");
        object.resize(object_size(algorithm.handle));
        check(
            BCryptGenerateSymmetricKey(
                algorithm.handle,
                &key.handle,
                object.data(),
                length(object.size()),
                mutable_bytes(material.first(16)),
                16,
                0),
            "create AES-128 key");
        std::copy_n(material.begin() + 16, prefix.size(), prefix.begin());
    }
};

std::array<std::uint8_t, 12>
nonce(const Direction &direction, View counter)
{
    std::array<std::uint8_t, 12> result{};
    std::copy(direction.prefix.begin(), direction.prefix.end(), result.begin());
    std::copy_n(counter.begin(), 8, result.begin() + 4);
    return result;
}

Bytes
associated_data(View counter)
{
    auto domain = bytes("flowtunnel/record/v1");
    Bytes result(domain.begin(), domain.end());
    result.push_back(0);
    result.insert(result.end(), counter.begin(), counter.end());
    return result;
}

} // namespace

Bytes
new_client_hello(const Key &key, Mode mode, std::uint16_t port)
{
    if ((mode != Stream && mode != Datagram) || port == 0)
        throw std::runtime_error("invalid transport mode or destination port");
    Bytes hello(HelloSize);
    std::copy_n("FT01", 4, hello.begin());
    hello[4] = mode;
    hello[6] = static_cast<std::uint8_t>(port >> 8);
    hello[7] = static_cast<std::uint8_t>(port);
    check(
        BCryptGenRandom(nullptr, hello.data() + 8, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG), "generate session randomness");
    auto mac = authenticate(key, "flowtunnel/client-hello/v1", View(hello).first(40));
    std::copy(mac.begin(), mac.end(), hello.begin() + 40);
    return hello;
}

HelloInfo
verify_client_hello(const Key &key, View hello)
{
    if (hello.size() != HelloSize || !std::equal(hello.begin(), hello.begin() + 4, "FT01") || hello[5] != 0)
        throw std::runtime_error("protocol authentication failed");
    auto mode = static_cast<Mode>(hello[4]);
    auto port = static_cast<std::uint16_t>((static_cast<std::uint16_t>(hello[6]) << 8) | hello[7]);
    if ((mode != Stream && mode != Datagram) || port == 0 ||
        !constant_equal(hello.subspan(40), authenticate(key, "flowtunnel/client-hello/v1", hello.first(40))))
        throw std::runtime_error("protocol authentication failed");
    return { mode, port };
}

Accepted
accept_client_hello(const Key &key, View hello)
{
    verify_client_hello(key, hello);
    Bytes response(ResponseSize);
    check(
        BCryptGenRandom(nullptr, response.data(), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG), "generate session randomness");
    auto mac = authenticate(key, "flowtunnel/server-hello/v1", hello, View(response).first(32));
    std::copy(mac.begin(), mac.end(), response.begin() + 32);
    return { response, std::shared_ptr<Session>(new Session(key, hello, response, false)) };
}

std::shared_ptr<Session>
client_session(const Key &key, View hello, View response)
{
    verify_client_hello(key, hello);
    if (response.size() != ResponseSize ||
        !constant_equal(
            response.subspan(32), authenticate(key, "flowtunnel/server-hello/v1", hello, response.first(32))))
        throw std::runtime_error("protocol authentication failed");
    return std::shared_ptr<Session>(new Session(key, hello, response, true));
}

struct Session::Impl
{
    std::mutex send_mutex, receive_mutex;
    Direction send, receive;
    std::uint64_t send_count{}, receive_high{};
    std::array<std::uint64_t, 16> receive_bits{};

    Impl(View send_material, View receive_material) : send(send_material), receive(receive_material) {}

    void commit(std::uint64_t count)
    {
        if (count > receive_high)
        {
            auto shift = count - receive_high;
            if (shift >= 1024)
            {
                receive_bits.fill(0);
            }
            else
            {
                auto words = static_cast<std::size_t>(shift / 64);
                auto bits = static_cast<unsigned>(shift % 64);
                for (std::size_t i = receive_bits.size(); i-- > 0;)
                {
                    std::uint64_t value{};
                    if (i >= words)
                    {
                        value = receive_bits[i - words] << bits;
                        if (bits != 0 && i > words)
                            value |= receive_bits[i - words - 1] >> (64 - bits);
                    }
                    receive_bits[i] = value;
                }
            }
            receive_high = count;
        }
        auto distance = receive_high - count;
        receive_bits[distance / 64] |= std::uint64_t{ 1 } << (distance % 64);
    }
};

Session::Session(const Key &key, View hello, View response, bool client)
{
    auto salt = hash(false, {}, { hello, response });
    auto outgoing =
        derive_material(key, salt, client ? "flowtunnel/client-to-server/v1" : "flowtunnel/server-to-client/v1");
    auto incoming =
        derive_material(key, salt, client ? "flowtunnel/server-to-client/v1" : "flowtunnel/client-to-server/v1");
    impl_ = std::make_unique<Impl>(outgoing, incoming);
    SecureZeroMemory(outgoing.data(), outgoing.size());
    SecureZeroMemory(incoming.data(), incoming.size());
}

Session::~Session() = default;

Bytes
Session::seal(View plaintext)
{
    std::lock_guard lock(impl_->send_mutex);
    if (impl_->send_count == std::numeric_limits<std::uint64_t>::max())
        throw std::runtime_error("record counter exhausted");
    auto size = length(plaintext.size());
    Bytes output(plaintext.size() + RecordOverhead);
    store64(output.data(), ++impl_->send_count);
    auto counter = View(output).first(8);
    auto iv = nonce(impl_->send, counter);
    auto aad = associated_data(counter);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = iv.data();
    info.cbNonce = length(iv.size());
    info.pbAuthData = aad.data();
    info.cbAuthData = length(aad.size());
    info.pbTag = output.data() + 8 + plaintext.size();
    info.cbTag = 16;
    ULONG written{};
    check(
        BCryptEncrypt(
            impl_->send.key.handle,
            mutable_bytes(plaintext),
            size,
            &info,
            nullptr,
            0,
            output.data() + 8,
            size,
            &written,
            0),
        "encrypt AES-GCM record");
    if (written != size)
        throw std::runtime_error("unexpected AES-GCM output size");
    return output;
}

Bytes
Session::open(View record)
{
    std::lock_guard lock(impl_->receive_mutex);
    if (record.size() < RecordOverhead)
        throw std::runtime_error("protocol authentication failed");
    auto count = load64(record.first(8));
    if (count == 0)
        throw std::runtime_error("invalid record counter");
    bool replay = false;
    if (count <= impl_->receive_high)
    {
        auto distance = impl_->receive_high - count;
        replay = distance >= 1024 || (impl_->receive_bits[distance / 64] & (std::uint64_t{ 1 } << (distance % 64))) != 0;
    }
    auto size = length(record.size() - RecordOverhead);
    auto iv = nonce(impl_->receive, record.first(8));
    auto aad = associated_data(record.first(8));
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = iv.data();
    info.cbNonce = length(iv.size());
    info.pbAuthData = aad.data();
    info.cbAuthData = length(aad.size());
    info.pbTag = mutable_bytes(record.last(16));
    info.cbTag = 16;
    Bytes output(size);
    // A null output pointer asks CNG for a size and skips tag verification.
    std::uint8_t empty_output{};
    ULONG written{};
    auto status = BCryptDecrypt(
        impl_->receive.key.handle,
        mutable_bytes(record.subspan(8, size)),
        size,
        &info,
        nullptr,
        0,
        output.empty() ? &empty_output : output.data(),
        size,
        &written,
        0);
    if (status < 0)
        throw std::runtime_error("protocol authentication failed");
    if (written != size)
        throw std::runtime_error("unexpected AES-GCM output size");
    if (replay)
        throw ReplayError();
    impl_->commit(count);
    return output;
}

} // namespace ft
