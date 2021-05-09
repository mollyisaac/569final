
#include "FastMath.h"

#include <cmath>


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace OpenAFIS
{


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Hot path: no (loading only)
// Domain: 0 < x < max(Field::MinutiaCoordType)^2
// Maximum result is also a dimension (default uint8_t), so a table is viable and quite small (<64K)...
//
FastMath::SquareRoots::SquareRoots()
    : m_values([]() {
        static Values v;
        for (size_t i = 0; i < Max; ++i) {
            v.at(i) = static_cast<Field::MinutiaDistanceType>(std::lround(std::sqrt(i)));
        }
        return &v;
    }())
{
}

Field::MinutiaDistanceType FastMath::isqrt(const unsigned int x)
{
    static const SquareRoots Table;
    return Table.get(x);
}


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Hot path: yes
// Domain: -max(Field::MinutiaCoordType) < x < max(Field::MinutiaCoordType), y is the same so lookups possible (they weigh about ~1MB with floats).
// Profiling reveals ~2x speedup using lookups vs CRT (with SSE2).
// TODO: research cordic options https://www.coranac.com/documents/arctangent/ for memory constrained builds...
//
FastMath::ArcTangents::ArcTangents()
    : m_values([]() {
        static Values v;
        for (auto x = Min; x < Max; ++x) {
            for (auto y = Min; y < Max; ++y) {
                const auto t = ::atan2f(x, y);
                if constexpr (std::is_same_v<Field::AngleType, float>) {
                    v.at(x - Min).at(y - Min) = static_cast<Field::AngleType>(t);
                }
                if constexpr (std::is_same_v<Field::AngleType, int16_t>) {
                    v.at(x - Min).at(y - Min) = static_cast<Field::AngleType>(std::lround(t * Radians8));
                }
            }
        }
        return &v;
    }())
{
}

Field::AngleType FastMath::atan2(const Field::MinutiaCoordType x, const Field::MinutiaCoordType y)
{
    static const ArcTangents Table;
    return Table.get(x, y);
}


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Hot path: yes
//
FastMath::Cosines::Cosines()
    : m_values([]() {
        static Values v;
        for (auto i = Min; i <= Max; ++i) {
            v.at(i - Min) = ::cosf(static_cast<float>(i) / FastMath::Radians8);
        }
        return &v;
    }())
{
}

float FastMath::cos(const Field::AngleType theta)
{
    if constexpr (std::is_same_v<Field::AngleType, float>) {
        return ::cosf(theta);
    }
    if constexpr (std::is_same_v<Field::AngleType, int16_t>) {
        static const Cosines Table;
        return Table.get(theta);
    }
}


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Hot path: yes
//
FastMath::Sines::Sines()
    : m_values([]() {
        static Values v;
        for (auto i = Min; i <= Max; ++i) {
            v.at(i - Min) = ::sinf(static_cast<float>(i) / FastMath::Radians8);
        }
        return &v;
    }())
{
}

float FastMath::sin(const Field::AngleType theta)
{
    if constexpr (std::is_same_v<Field::AngleType, float>) {
        return ::sinf(theta);
    }
    if constexpr (std::is_same_v<Field::AngleType, int16_t>) {
        static const Sines Table;
        return Table.get(theta);
    }
}


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Hot path: no (loading only)
//
Field::AngleSize FastMath::degreesToRadians(const uint16_t theta)
{
    if constexpr (std::is_same_v<Field::AngleType, float>) {
        static constexpr float Factor = PI / 180.0f;
        return static_cast<float>(theta) * Factor;
    }
    if constexpr (std::is_same_v<Field::AngleType, int16_t>) {
        static constexpr float Factor = PI / 180.0f * Radians8;
        return static_cast<Field::AngleSize>(std::lround(static_cast<float>(theta) * Factor));
    }
}


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Hot path: yes
// Equation 1...
//
Field::AngleType FastMath::minimumAngle(const Field::AngleType a, const Field::AngleType b)
{
    const auto d = diff(a, b);

    if constexpr (std::is_same_v<Field::AngleType, float>) {
        return std::min(static_cast<float>(d), FastMath::TwoPI - static_cast<float>(d));
    }
    if constexpr (std::is_same_v<Field::AngleType, int16_t>) {
        return std::min(d, static_cast<Field::AngleType>(FastMath::TwoPI8 - d));
    }
}


//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Hot path: yes
// Equation 2...
//
Field::AngleType FastMath::rotateAngle(const Field::AngleType a, const Field::AngleType b)
{
    if (b > a) {
        return b - a;
    }
    if constexpr (std::is_same_v<Field::AngleType, float>) {
        return static_cast<float>(b - a) + FastMath::TwoPI;
    }
    if constexpr (std::is_same_v<Field::AngleType, int16_t>) {
        return b - a + FastMath::TwoPI8;
    }
}
}