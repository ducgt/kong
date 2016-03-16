local ldap = require "kong.plugins.ldap-auth.ldap"


local _M = {}

local function bind_authenticate(given_username, given_password, conf)
  local params = {
    who = conf.attribute.."="..given_username..","..conf.base_dn,
    password = given_password,
  }
  local ok, err

  local sock = ngx.socket.tcp()

  ok, err = sock:connect(conf.ldap_host, conf.ldap_port)
  if not ok then
    return false, err
  end
  
  local binding, error = ldap.bindRequest(sock, params)
  return binding, error
end

function _M.authenticate(given_username, given_password, conf)
  return bind_authenticate(given_username, given_password, conf)
end

return _M
