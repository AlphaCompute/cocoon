#include "tee/cocoon/RATLS.h"

namespace cocoon {

td::Result<RATLSPolicyConfig> parse_ratls_policy_from_json(td::JsonObject& obj) {
  RATLSPolicyConfig policy;

  auto r_tdx_config_field = obj.extract_optional_field("tdx_config", td::JsonValue::Type::Object);
  if (r_tdx_config_field.is_ok() && r_tdx_config_field.ok().type() == td::JsonValue::Type::Object) {
    TRY_RESULT(tdx_config, tdx::parse_policy_config(r_tdx_config_field.ok_ref().get_object()));
    policy.tdx_config = std::move(tdx_config);
  }

  auto r_sev_config_field = obj.extract_optional_field("sev_config", td::JsonValue::Type::Object);
  if (r_sev_config_field.is_ok() && r_sev_config_field.ok().type() == td::JsonValue::Type::Object) {
    TRY_RESULT(sev_config, sev::parse_policy_config(r_sev_config_field.ok_ref().get_object()));
    policy.sev_config = std::move(sev_config);
  }

  return policy;
}

td::StringBuilder& operator<<(td::StringBuilder& sb, const RATLSPolicyConfig& config) {
  sb << "{\n";
  sb << "  tdx_config:" << config.tdx_config;
  sb << ", sev_config:" << config.sev_config;
  sb << "}";

  return sb;
}

}  // namespace cocoon
