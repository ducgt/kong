local DaoError = require "kong.dao.error"
local constants = require "kong.constants"

local function validate_cert(v)
  local ssl = require "ngx.ssl"
  local der = ssl.cert_pem_to_der(v)
  if der then
    return true, nil, { _cert_der_cache = base64.encode(der) }
  end
  return false, "Invalid SSL certificate"
end

local function validate_cacert(v)
  local ssl = require "ngx.ssl"
  local der = ssl.cert_pem_to_der(v)
  if der then
    return true, nil, { _cacert_der_cache = base64.encode(der) }
  end
  return false, "Invalid SSL certificate"
end

local function validate_key(v)
  local ssl = require "ngx.ssl"
  local der = ssl.priv_key_pem_to_der(v)
  if der then
    return true, nil, { _key_der_cache = base64.encode(der) }
  end
  return false, "Invalid SSL certificate key"
end

return {
fields = {
    ldap_host = {required = true, type = "string"},
    ldap_port = {required = true, type = "number"},
    start_tls = {required = true, type = "boolean", default = false},
    authenticate_server = {required = true, type = "boolean", default = false},
    cert = {required = false, type = "string", func = validate_cert},
    key = {required = false, type = "string", func = validate_key},
    cert_chain = {required = false, type = "string", func = validate_cacert},
    base_dn = {required = true, type = "string"},
    attribute = {required = true, type = "string"},
    cache_ttl = {required = true, type = "number", default = 60},
    hide_credentials = {type = "boolean", default = false},
    timeout = {type = "number", default = 10000},
    keepalive = {type = "number", default = 60000},
    
    -- Internal use
    _cert_der_cache = { type = "string" },
    _key_der_cache = { type = "string" },
    _cacert_der_cache = { type = "string" }
  },
  self_check = function(schema, plugin_t, dao, is_update)
    if plugin_t["ldap_protocol"] == "ldaps" and plugin_t["start_tls"] then
      return false, DaoError("You cannot set start_tls to 'true' when protocol is selected as 'ldaps'", constants.DATABASE_ERROR_TYPES.SCHEMA)
    end
    
    return true
  end
}
