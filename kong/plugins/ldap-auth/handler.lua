local access = require "kong.plugins.ldap-auth.access"
local BasePlugin = require "kong.plugins.base_plugin"

local LdapAuthHandler = BasePlugin:extend()

function LdapAuthHandler:new()
  LdapAuthHandler.super.new(self, "ldap-auth")
end

function LdapAuthHandler:certificate(conf)
  LdapAuthHandler.super.certificate(self)
  local ssl = require "ngx.ssl"
  ssl.clear_certs()

  local data = cache.get_or_set(cache.ldap_ssl_data(ngx.ctx.api.id), function()
    local result = {
      cert_der = ngx.decode_base64(conf._cert_der_cache),
      key_der = ngx.decode_base64(conf._key_der_cache),
      cacert_der = ngx.decode_base64(conf._cert_der_cache)
    }
    return result
  end)

  local ok, err = ssl.set_der_cert(data.cert_der)
  if not ok then
    ngx.log(ngx.ERR, "failed to set DER cert: ", err)
    return
  end
  ok, err = ssl.set_der_priv_key(data.key_der)
  if not ok then
    ngx.log(ngx.ERR, "failed to set DER private key: ", err)
    return
  end
end

function LdapAuthHandler:access(conf)
  LdapAuthHandler.super.access(self)
  access.execute(conf)
end

LdapAuthHandler.PRIORITY = 1000

return LdapAuthHandler

