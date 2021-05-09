
#include "TemplateISO19794_2_2005.h"
#include "Log.h"

#include <cstring>
#include <fstream>


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace OpenAFIS
{


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
template <class I, class F> const unsigned char TemplateISO19794_2_2005<I, F>::MagicVersion[] = { 'F', 'M', 'R', 0, ' ', '2', '0', 0 };


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
template <class I, class F> bool TemplateISO19794_2_2005<I, F>::load(const std::string& path)
{
    std::ifstream f(path, std::ifstream::in | std::ifstream::binary);
    if (!f) {
        Log::error("unable to open ", path);
        return false;
    }
    thread_local static std::vector<uint8_t> data(MaximumLength);
    f.read(reinterpret_cast<char*>(data.data()), data.size());
    if ((f.rdstate() & std::ifstream::eofbit) == 0) {
        Log::error("filesize > MaximumLength ", path);
        return false;
    }
    return load(data.data(), static_cast<size_t>(f.gcount()));
}


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// https://www.iso.org/standard/38746.html
// https://www.nist.gov/services-resources/software/biomdi-software-tools-supporting-standard-biometric-data-interchange
// https://templates.machinezoo.com/iso-19794-2-2005
//
template <class I, class F> bool TemplateISO19794_2_2005<I, F>::load(const uint8_t* data, const size_t length)
{
    if (length < MinimumLength) {
        Log::error("length < MinimumLength; ", length);
        return false;
    }
    if (length > MaximumLength) {
        Log::error("length > MaximumLength; ", length);
        return false;
    }

    // return a pointer to struct at data provided all reads from that struct would not exceed bounds
    // also increment the source pointer to the next element...
    const auto safeRead = [data, length](auto** readFrom) {
        using T = decltype(*readFrom);
        constexpr auto sz = sizeof(**readFrom);
        if (reinterpret_cast<const uint8_t*>(*readFrom) - data + sz > length) {
            Log::error("data invalid; attempted invalid read @", readFrom);
            const void* np { nullptr };
            return reinterpret_cast<T>(np);
        }
        const auto* _p = *readFrom;
        *reinterpret_cast<const uint8_t**>(readFrom) += sz;

        // check alignment - platforms that support unaligned access (like x86) _could_ just return p
        // realigning here does improve performance though & is a requirement for some platforms (like arm) where unaligned access is UB...
        if (reinterpret_cast<uintptr_t>(_p) % sizeof(void*) == 0) {
            return _p;
        }
        thread_local static std::vector<uint8_t> buff(LargestStruct);
        if (sz > buff.size()) {
            Log::error("struct exceeded buffer while aligning @", readFrom);
            *readFrom = nullptr;
            return *readFrom;
        }
        memcpy(buff.data(), _p, sz);
        const void* bp { buff.data() };
        return reinterpret_cast<T>(bp);
    };

    const auto* p = data;
    if (std::memcmp(p, &MagicVersion, sizeof(MagicVersion)) != 0) {
        Log::error("invalid magic; unsupported format");
        return false;
    }
    p = &p[sizeof(MagicVersion)];

    const auto* h = safeRead(reinterpret_cast<const _Header**>(&p));
    if (!h) {
        return false;
    }
    if (swap32(h->totalLength) != length) {
        Log::error("totalLength != length");
        return false;
    }
    std::vector<std::vector<Minutia>> fps;
    fps.reserve(h->fingerPrintCount);

    for (auto f = 0u; f < fps.capacity(); ++f) {
        const auto* fp = safeRead(reinterpret_cast<const _FingerPrint**>(&p));
        if (!fp) {
            return false;
        }
        auto& minutiae = fps.emplace_back();
        minutiae.reserve(std::min(fp->minutiaCount, static_cast<uint8_t>(Template<I, F>::MaximumMinutiae)));

        auto m = 0u;
        for (; m < minutiae.capacity(); ++m) {
            const auto* mp = safeRead(reinterpret_cast<const _Minutia**>(&p));
            if (!mp) {
                return false;
            }
            const auto adjustedAngle = [mp]() -> uint16_t {
                const auto a = static_cast<unsigned short>(360.0f - static_cast<float>(mp->angle) * (360.0f / 256.0f));
                return a > 360 ? a - 360 : a;
            };
            minutiae.emplace_back(Minutia::Type((mp->type_X & 0x00c0) >> 6), static_cast<uint16_t>((mp->type_X & 0x3f) << 8 | (mp->type_X & 0xff00) >> 8),
                static_cast<uint16_t>((mp->rfu_Y & 0x3f) << 8 | (mp->rfu_Y & 0xff00) >> 8), adjustedAngle());
        }
        for (; m < fp->minutiaCount; ++m) {
            const auto* mp = safeRead(reinterpret_cast<const _Minutia**>(&p));
            if (!mp) {
                return false;
            }
        }
        // skip extension data at the end...
        const auto* ex = safeRead(reinterpret_cast<const uint16_t**>(&p));
        if (!ex) {
            return false;
        }
        uint16_t extensionData;
        memcpy(&extensionData, ex, sizeof(extensionData));
        p = &p[swap16(extensionData)];
    }
    return Template<I, F>::load(std::make_pair(swap16(h->width), swap16(h->height)), fps);
}


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Explicit instantiations...
//
template class TemplateISO19794_2_2005<uint16_t, Fingerprint>;
template class TemplateISO19794_2_2005<uint16_t, FingerprintRenderable>;
template class TemplateISO19794_2_2005<uint32_t, Fingerprint>;
template class TemplateISO19794_2_2005<uint32_t, FingerprintRenderable>;
template class TemplateISO19794_2_2005<uint64_t, Fingerprint>;
template class TemplateISO19794_2_2005<uint64_t, FingerprintRenderable>;
template class TemplateISO19794_2_2005<std::string, Fingerprint>;
template class TemplateISO19794_2_2005<std::string, FingerprintRenderable>;
}
