#pragma once

#include <map>
#include <string>

#include "td/utils/JsonBuilder.h"
#include "td/utils/UInt.h"

#include "tee/cocoon/sev/PolicyConfig.h"
#include "tee/cocoon/sev/RATLS.h"
#include "tee/cocoon/tdx/PolicyConfig.h"
#include "tee/cocoon/tdx/RATLS.h"

namespace cocoon {

struct RATLSPolicyConfig {
  tdx::PolicyConfig tdx_config;
  sev::PolicyConfig sev_config;

  std::map<std::string, std::string> parameters;
};

td::Result<RATLSPolicyConfig> parse_ratls_policy_from_json(td::JsonObject& obj);
td::StringBuilder& operator<<(td::StringBuilder& sb, const RATLSPolicyConfig& config);

class RATLSInterface {
 public:
  virtual ~RATLSInterface() = default;

 public:
  virtual td::Result<sev::RATLSAttestation> validate(const td::UInt512& user_claims,
                                                     const sev::RATLSExtensions& extensions) const = 0;

  virtual td::Result<tdx::RATLSAttestation> validate(const td::UInt512& user_claims,
                                                     const tdx::RATLSExtensions& extensions) const = 0;
};

}  // namespace cocoon
