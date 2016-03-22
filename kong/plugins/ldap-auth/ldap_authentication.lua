local ldap = require "kong.plugins.ldap-auth.ldap"


local _M = {}

local function bind_authenticate(given_username, given_password, conf)
  local who = conf.attribute.."="..given_username..","..conf.base_dn
  
  local sock = ngx.socket.tcp()
  sock:settimeout(conf.timeout)
  local ok, error = sock:connect(conf.ldap_host, conf.ldap_port)
  if not ok then
    return false, error
  end
  
  if conf.start_tls then
    local success, error = ldap.start_tls(sock)
    if not success then
      return false, error
    end
    local _, error = sock:sslhandshake(true, conf.ldap_host, false)
    if error ~= nil then
       return false, "failed to do SSL handshake with "..conf.ldap_host..":"..tostring(conf.ldap_port)..": ".. error
    end
  end  
  
  local binding, error = ldap.bind_request(sock, who, given_password)
  
  sock:setkeepalive(conf.keepalive)
  return binding, error
end

function _M.authenticate(given_username, given_password, conf)
  return bind_authenticate(given_username, given_password, conf)
end

return _M
