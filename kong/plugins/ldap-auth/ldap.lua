local asn1 = require "kong.plugins.ldap-auth.asn1"
local pack = require "lua_pack"
local bpack = string.pack
local bunpack = string.unpack
_M = {}

local ldapMessageId = 1

ERROR_MSG = {}
ERROR_MSG[1]  = "Initialization of LDAP library failed."
ERROR_MSG[4]  = "Size limit exceeded."
ERROR_MSG[13] = "Confidentiality required"
ERROR_MSG[32] = "No such object"
ERROR_MSG[34] = "Invalid DN"
ERROR_MSG[49] = "The supplied credential is invalid."

ERRORS = {
  LDAP_SUCCESS = 0,
  LDAP_SIZELIMIT_EXCEEDED = 4
}

APPNO = {
  BindRequest = 0,
  BindResponse = 1,
  UnbindRequest = 2
}

local tagEncoder = {}

tagEncoder['table'] = function(self, val)
  if (val._ldap == '0A') then
    local ival = self.encodeInt(val[1])
    local len = self.encodeLength(#ival)
    return bpack('XAA', '0A', len, ival)
  end
  if (val._ldaptype) then
    local len
    if val[1] == nil or #val[1] == 0 then
      return bpack('XC', val._ldaptype, 0)
    else
      len = self.encodeLength(#val[1])
      return bpack('XAA', val._ldaptype, len, val[1])
    end
  end

  local encVal = ""
  for _, v in ipairs(val) do
    encVal = encVal .. encode(v) -- todo: buffer?
  end
  local tableType = "\x30"
  if (val["_snmp"]) then
    tableType = bpack("X", val["_snmp"])
  end
  return bpack('AAA', tableType, self.encodeLength(#encVal), encVal)
end


function encode(val)
  local encoder = asn1.ASN1Encoder:new()
  local encValue
  encoder:registerTagEncoders(tagEncoder)
  encValue = encoder:encode(val)
  if encValue then
    return encValue
  end

  return ''
end

local tagDecoder = {}

tagDecoder["0A"] = function( self, encStr, elen, pos )
  return self.decodeInt(encStr, elen, pos)
end

tagDecoder["8A"] = function( self, encStr, elen, pos )
  return bunpack(encStr, "A" .. elen, pos)
end

tagDecoder["31"] = function( self, encStr, elen, pos )
  return pos, nil
end

function decode(encStr, pos)
  -- register the LDAP specific tag decoders
  local decoder = asn1.ASN1Decoder:new()
  decoder:registerTagDecoders(tagDecoder)
  return decoder:decode(encStr, pos)
end


local function decodeSeq(encStr, len, pos)
  local seq = {}
  local sPos = 1
  local sStr
  pos, sStr = bunpack(encStr, "A" .. len, pos)
  if(sStr==nil) then
    return pos,seq
  end
  while (sPos < len) do
    local newSeq
    sPos, newSeq = decode(sStr, sPos)
    table.insert(seq, newSeq)
  end
  return pos, seq
end


function encodeLDAPOp( appno, isConstructed, data )
  local encoded_str = ""
  local asn1_type = asn1.BERtoInt( asn1.BERCLASS.Application, isConstructed, appno )
  encoded_str = encode( { _ldaptype = string.format("%X", asn1_type), data } )
  print("=====encoded_str=====", encoded_str)
  return encoded_str
end



function _M.bindRequest( socket, username, password)
  local ldapAuth = encode({ _ldaptype = 80, password })
  local bindReq = encode(3) .. encode(username) .. ldapAuth
  ngx.log(ngx.DEBUG, bindReq)
  local ldapMsg = encode(ldapMessageId) .. encodeLDAPOp( APPNO.BindRequest, true, bindReq )
  local packet
  local pos, packet_len, resultCode, tmp, len, _
  local response = {}
  local encoder = asn1.ASN1Encoder:new()
  local decoder = asn1.ASN1Decoder:new()

  encoder:registerTagEncoders(tagEncoder)
  decoder:registerTagDecoders(tagDecoder)

  packet = encoder:encodeSeq( ldapMsg )
  ldapMessageId = ldapMessageId +1
  socket:send(packet)
 local reader = socket:receiveuntil("\r\n")
 local data = reader()
  packet = reader()
  ngx.log(ngx.DEBUG, _M.hex(packet))
  print("length", #packet)
  pos, packet_len = decoder.decodeLength( packet, 2 )
  pos, response.messageID = decode( packet, pos )
  pos, tmp = bunpack(packet, "C", pos)
  pos, len = decoder.decodeLength( packet, pos )
  response.protocolOp = asn1.intToBER(tmp)
  local inspect = require("inspect")
  print(inspect(response))

  if response.protocolOp.number ~= APPNO.BindResponse then
    return false, string.format("Received incorrect Op in packet: %d, expected %d", response.protocolOp.number, APPNO.BindResponse)
  end

  pos, response.resultCode = decode( packet, pos )
  
  if ( response.resultCode ~= 0 ) then
    local error_msg
    pos, response.matchedDN = decode( packet, pos )
    pos, response.errorMessage = decode( packet, pos )
    error_msg = ERROR_MSG[response.resultCode]
    return false, string.format("\n  Error: %s\n  Details: %s",
      error_msg or "Unknown error occurred (code: " .. response.resultCode ..
      ")", response.errorMessage or "" )
  else
    return true, "Success"
  end
end


function _M.unbindRequest( socket )

  local ldapMsg, packet

  local encoder = asn1.ASN1Encoder:new()
  encoder:registerTagEncoders(tagEncoder)

  ldapMessageId = ldapMessageId +1
  ldapMsg = encode( ldapMessageId ) .. encodeLDAPOp( APPNO.UnbindRequest, false, nil)
  packet = encoder:encodeSeq(ldapMsg)
  socket:send(packet)
  return true, ""
end

return _M;
