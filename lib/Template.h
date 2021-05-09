#ifndef TEMPLATE_H
#define TEMPLATE_H


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#include "Fingerprint.h"

#include <vector>


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace OpenAFIS
{

// Any identifier you like - maybe a std::string for research, or uint16_t when memory is a constraint...
template <class I, class F> class Template
{
public:
    using IdType = I;
    using FingerprintType = F;
    using Minutiae = std::vector<Minutia>;
    using Fingerprints = std::vector<FingerprintType>;

    explicit Template(const IdType& id)
        : m_id(id)
    {
    }

    [[nodiscard]] const IdType& id() const { return m_id; }
    [[nodiscard]] const Fingerprints& fingerprints() const { return m_fps; }
    void clear() { m_fps.clear(); }
    [[nodiscard]] size_t bytes() const
    {
        return sizeof(*this) + std::accumulate(m_fps.begin(), m_fps.end(), size_t {}, [](size_t sum, const auto& fp) { return sum + fp.bytes(); });
    }

protected:
    static constexpr size_t MaximumFingerprints = 8;
    static constexpr size_t MinimumMinutiae = 2;
    static constexpr size_t MaximumMinutiae = 128;

    bool load(const Dimensions& dimensions, const std::vector<Minutiae>& fps);

private:
    IdType m_id;
    Fingerprints m_fps;
};
}

#endif // TEMPLATE_H
