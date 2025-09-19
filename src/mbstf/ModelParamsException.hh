#ifndef _MBS_TF_MODEL_PARAMS_EXCEPTION_HH_
#define _MBS_TF_MODEL_PARAMS_EXCEPTION_HH_
/******************************************************************************
 * 5G-MAG Reference Tools: MBS Traffic Function: Model Exception with Invalid Params
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
#include <map>
#include <optional>
#include <string>

#include "common.hh"
#include "openapi/model/ModelException.hh"
#include "openapi/model/ProblemCause.hh"

MBSTF_NAMESPACE_START

class ModelParamsException : public fiveg_mag_reftools::ModelException {
public:
    ModelParamsException(const std::string &ex_reason, const std::string &ex_classname, const std::string &ex_parameter = std::string(), const std::optional<fiveg_mag_reftools::ProblemCause> &ex_cause = std::nullopt)
        :fiveg_mag_reftools::ModelException(ex_reason, ex_classname, ex_parameter, ex_cause)
        ,invalidParams()
    {
        if (!ex_parameter.empty()) {
            addInvalidParameter(ex_parameter, ex_reason);
        }
    };

    ModelParamsException(const ModelParamsException &other) noexcept
        :fiveg_mag_reftools::ModelException(other)
        ,invalidParams(other.invalidParams)
    {};

    virtual ~ModelParamsException() {};

    void addInvalidParameter(const std::string &parameter, const std::string &reason) {
        invalidParams.insert(std::make_pair(parameter, reason));
    };

    std::map<std::string, std::string> invalidParams;
private:
    ModelParamsException() = delete;
};

MBSTF_NAMESPACE_STOP

/* vim:ts=8:sts=4:sw=4:expandtab:
 */
#endif /* _MBS_TF_MODEL_PARAMS_EXCEPTION_HH_ */
