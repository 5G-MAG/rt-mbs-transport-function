/******************************************************************************
 * 5G-MAG Reference Tools: MBS Transport Function: BitRate string handler
 ******************************************************************************
 * Copyright: (C)2025 British Broadcasting Corporation
 * Author(s): David Waring <david.waring2@bbc.co.uk>
 * License: 5G-MAG Public License v1
 *
 * Licensed under the License terms and conditions for use, reproduction, and
 * distribution of 5G-MAG software (the “License”).  You may not use this file
 * except in compliance with the License.  You may obtain a copy of the License at
 * https://www.5g-mag.com/reference-tools.  Unless required by applicable law or
 * agreed to in writing, software distributed under the License is distributed on
 * an “AS IS” BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied.
 *
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */
#include <exception>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "common.hh"

#include "BitRate.hh"

static const int g_BitRate_formatting_xindex = std::ios_base::xalloc();

namespace{
class BitRateFormattingOptions {
public:
    BitRateFormattingOptions() :m_units(MBSTF_NAMESPACE_NAME(BitRate)::BIT_RATE_UNITS_AUTO) {};
    ~BitRateFormattingOptions() {};

    MBSTF_NAMESPACE_NAME(BitRate::UnitsType) units() const { return m_units; };
    BitRateFormattingOptions &units(MBSTF_NAMESPACE_NAME(BitRate::UnitsType) units) {
        m_units = units;
        return *this;
    };

private:
    MBSTF_NAMESPACE_NAME(BitRate::UnitsType) m_units;
};
}

static BitRateFormattingOptions &get_bitrate_formatting(std::ios_base &ios);

MBSTF_NAMESPACE_START

BitRate::BitRate()
    :m_bitRate(0.0)
{
}

BitRate::BitRate(const std::string &bit_rate_str)
    :m_bitRate(0.0)
{
    *this = bit_rate_str;
}

BitRate::BitRate(BitRate &&other)
    :m_bitRate(other.m_bitRate)
{
}

BitRate::BitRate(const BitRate &other)
    :m_bitRate(other.m_bitRate)
{
}

BitRate &BitRate::operator=(const std::string &bit_rate_str)
{
    auto pos = bit_rate_str.find_first_of(' ');
    if (pos == std::string::npos) {
        /* no units, just try parse as double */
        m_bitRate = std::stod(bit_rate_str);
    } else {
        std::string_view bit_rate(static_cast<std::string_view>(bit_rate_str));
        std::string num(bit_rate.substr(0, pos));
        std::string_view units(bit_rate.substr(pos+1));
        double multiplier = 1.0;
        if (units == "Tbps") {
            multiplier = 1e12;
        } else if (units == "Gbps") {
            multiplier = 1e9;
        } else if (units == "Mbps") {
            multiplier = 1e6;
        } else if (units == "Kbps") {
            multiplier = 1e3;
        } else if (units == "bps" || units.empty()) {
            /* No multiplier change */
        } else {
            std::ostringstream oss;
            oss << "Unknown BitRate units \"" << units << "\"";
            throw std::invalid_argument(oss.str());
        }
        size_t idx = 0;
        m_bitRate = std::stod(num, &idx) * multiplier;
        if (idx != num.size()) {
            throw std::invalid_argument("Invalid bitrate value");
        }
    }
    return *this;
}

BitRate &BitRate::operator=(BitRate &&other)
{
    m_bitRate = other.m_bitRate;
    return *this;
}

BitRate &BitRate::operator=(const BitRate &other)
{
    m_bitRate = other.m_bitRate;
    return *this;
}

int BitRate::compare(const BitRate &other) const
{
    double diff = m_bitRate - other.m_bitRate;
    if (diff == 0.0) return 0;
    if (diff < 0.0) return -1;
    return 1;
}

std::string BitRate::str(BitRate::UnitsType units, int width) const
{
    double divisor = 1.0;
    const char *units_str = "";

    switch (units) {
    case BIT_RATE_UNITS_AUTO:
        if (m_bitRate >= 1000000000000.0) {
            divisor = 1000000000000.0;
            units_str = " Tbps";
        } else if (m_bitRate >= 1000000000.0) {
            divisor = 1000000000.0;
            units_str = " Gbps";
        } else if (m_bitRate >= 1000000.0) {
            divisor = 1000000.0;
            units_str = " Mbps";
        } else if (m_bitRate >= 1000.0) {
            divisor = 1000.0;
            units_str = " Kbps";
        }
        break;
    case BIT_RATE_UNITS_KBPS:
        divisor = 1000.0;
        units_str = " Kbps";
        break;
    case BIT_RATE_UNITS_MBPS:
        divisor = 1000000.0;
        units_str = " Mbps";
        break;
    case BIT_RATE_UNITS_GBPS:
        divisor = 1000000000.0;
        units_str = " Gbps";
        break;
    case BIT_RATE_UNITS_TBPS:
        divisor = 1000000000000.0;
        units_str = " Tbps";
        break;
    default:
        break;
    }

    std::ostringstream oss;
    if (width >= 0) {
        oss << std::setw(width);
    }
    oss << (m_bitRate/divisor) << units_str;

    return oss.str();
}

std::ostream &BitRate::choose(std::ostream &os)
{
    os << units(BIT_RATE_UNITS_AUTO);
    return os;
}

std::ostream &BitRate::bps(std::ostream &os)
{
    os << units(BIT_RATE_UNITS_BPS);
    return os;
}

std::ostream &BitRate::kbps(std::ostream &os)
{
    os << units(BIT_RATE_UNITS_KBPS);
    return os;
}

std::ostream &BitRate::mbps(std::ostream &os)
{
    os << units(BIT_RATE_UNITS_MBPS);
    return os;
}

std::ostream &BitRate::gbps(std::ostream &os)
{
    os << units(BIT_RATE_UNITS_GBPS);
    return os;
}

std::ostream &BitRate::tbps(std::ostream &os)
{
    os << units(BIT_RATE_UNITS_TBPS);
    return os;
}

MBSTF_NAMESPACE_STOP

std::ostream &operator<<(std::ostream &os, const MBSTF_NAMESPACE_NAME(BitRate) &bit_rate)
{
    os << bit_rate.str(get_bitrate_formatting(os).units(), os.width());
    return os;
}

std::ostream &operator<<(std::ostream &os, const MBSTF_NAMESPACE_NAME(BitRate::_SetUnits) &units)
{
    auto &opts = get_bitrate_formatting(os);
    opts.units(units.units);
    return os;
}

static BitRateFormattingOptions &get_bitrate_formatting(std::ios_base &ios)
{
    auto &pword = ios.pword(g_BitRate_formatting_xindex);
    if (pword == nullptr) {
        pword = reinterpret_cast<void*>(new BitRateFormattingOptions());
        ios.register_callback([](std::ios_base::event evt, std::ios_base& str, int idx){
            BitRateFormattingOptions *options = reinterpret_cast<BitRateFormattingOptions*>(str.pword(idx));
            if (evt == std::ios_base::erase_event) {
                if (options) delete options;
            }
        }, g_BitRate_formatting_xindex);
    }
    return *reinterpret_cast<BitRateFormattingOptions*>(pword);
}

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
