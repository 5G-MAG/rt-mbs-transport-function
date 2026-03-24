#ifndef _MBS_TF_BIT_RATE_HH_
#define _MBS_TF_BIT_RATE_HH_
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
#include <iostream>
#include <string>

#include "common.hh"

MBSTF_NAMESPACE_START

class BitRate {
public:
    enum UnitsType {
        BIT_RATE_UNITS_AUTO = 0,
        BIT_RATE_UNITS_BPS,
        BIT_RATE_UNITS_KBPS,
        BIT_RATE_UNITS_MBPS,
        BIT_RATE_UNITS_GBPS,
        BIT_RATE_UNITS_TBPS
    };
    struct _SetUnits { UnitsType units; };

    BitRate();
    BitRate(const std::string &bit_rate_str);
    BitRate(BitRate &&other);
    BitRate(const BitRate &other);

    virtual ~BitRate() {};

    BitRate &operator=(const std::string &bit_rate_str);
    BitRate &operator=(BitRate &&other);
    BitRate &operator=(const BitRate &other);

    bool operator==(const BitRate &other) { return compare(other) == 0; };
    bool operator!=(const BitRate &other) { return compare(other) != 0; };
    bool operator<(const BitRate &other) { return compare(other) < 0; };
    bool operator<=(const BitRate &other) { return compare(other) <= 0; };
    bool operator>(const BitRate &other) { return compare(other) > 0; };
    bool operator>=(const BitRate &other) { return compare(other) >= 0; };

    int compare(const BitRate &other) const;

    double bitRate() const { return m_bitRate; };
    std::string str(UnitsType units=BIT_RATE_UNITS_AUTO, int width=-1) const;

    /* ostream manipulators */
    static inline _SetUnits units(UnitsType __units) { return { __units }; };
    static std::ostream &choose(std::ostream &os);
    static std::ostream &bps(std::ostream &os);
    static std::ostream &kbps(std::ostream &os);
    static std::ostream &mbps(std::ostream &os);
    static std::ostream &gbps(std::ostream &os);
    static std::ostream &tbps(std::ostream &os);

private:
    double m_bitRate;
};

MBSTF_NAMESPACE_STOP

std::ostream &operator<<(std::ostream &os, const MBSTF_NAMESPACE_NAME(BitRate) &bit_rate);
std::ostream &operator<<(std::ostream &os, const MBSTF_NAMESPACE_NAME(BitRate::_SetUnits) &bit_rate);

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_BIT_RATE_HH_ */
