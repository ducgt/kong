local asn1 = require "ber"
local bin = require "bin"

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

--- Application constants
-- @class table
-- @name APPNO
APPNO = {
  BindRequest = 0,
  BindResponse = 1,
  UnbindRequest = 2,
  SearchRequest = 3,
  SearchResponse = 4,
  SearchResDone = 5
}

-- Filter operation constants
FILTER = {
  _and = 0,
  _or = 1,
  _not = 2,
  equalityMatch = 3,
  substrings = 4,
  greaterOrEqual = 5,
  lessOrEqual = 6,
  present = 7,
  approxMatch = 8,
  extensibleMatch = 9
}

-- Scope constants
SCOPE = {
  base=0,
  one=1,
  sub= 2,
  children=3,
  default = 0
}

-- Deref policy constants
DEREFPOLICY = {
  never=0,
  searching=1,
  finding = 2,
  always=3,
  default = 0
}

-- LDAP specific tag encoders
local tagEncoder = {}

tagEncoder['table'] = function(self, val)
  if (val._ldap == '0A') then
    local ival = self.encodeInt(val[1])
    local len = self.encodeLength(#ival)
    return bin.pack('HAA', '0A', len, ival)
  end
  if (val._ldaptype) then
    local len
    if val[1] == nil or #val[1] == 0 then
      return bin.pack('HC', val._ldaptype, 0)
    else
      len = self.encodeLength(#val[1])
      return bin.pack('HAA', val._ldaptype, len, val[1])
    end
  end

  local encVal = ""
  for _, v in ipairs(val) do
    encVal = encVal .. encode(v) -- todo: buffer?
  end
  local tableType = "\x30"
  if (val["_snmp"]) then
    tableType = bin.pack("H", val["_snmp"])
  end
  return bin.pack('AAA', tableType, self.encodeLength(#encVal), encVal)

end

---
-- Encodes a given value according to ASN.1 basic encoding rules for SNMP
-- packet creation.
-- @param val Value to be encoded.
-- @return Encoded value.
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


-- LDAP specific tag decoders
local tagDecoder = {}

tagDecoder["0A"] = function( self, encStr, elen, pos )
  return self.decodeInt(encStr, elen, pos)
end

tagDecoder["8A"] = function( self, encStr, elen, pos )
  return bin.unpack("A" .. elen, encStr, pos)
end

-- null decoder
tagDecoder["31"] = function( self, encStr, elen, pos )
  return pos, nil
end


---
-- Decodes an LDAP packet or a part of it according to ASN.1 basic encoding
-- rules.
-- @param encStr Encoded string.
-- @param pos Current position in the string.
-- @return The position after decoding
-- @return The decoded value(s).
function decode(encStr, pos)
  -- register the LDAP specific tag decoders
  local decoder = asn1.ASN1Decoder:new()
  decoder:registerTagDecoders( tagDecoder )
  return decoder:decode( encStr, pos )
end


---
-- Decodes a sequence according to ASN.1 basic encoding rules.
-- @param encStr Encoded string.
-- @param len Length of sequence in bytes.
-- @param pos Current position in the string.
-- @return The position after decoding.
-- @return The decoded sequence as a table.
local function decodeSeq(encStr, len, pos)
  local seq = {}
  local sPos = 1
  local sStr
  pos, sStr = bin.unpack("A" .. len, encStr, pos)
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

-- Encodes an LDAP Application operation and its data as a sequence
--
-- @param appno LDAP application number
-- @see APPNO
-- @param isConstructed boolean true if constructed, false if primitive
-- @param data string containing the LDAP operation content
-- @return string containing the encoded LDAP operation
function encodeLDAPOp( appno, isConstructed, data )
  local encoded_str = ""
  local asn1_type = asn1.BERtoInt( asn1.BERCLASS.Application, isConstructed, appno )

  encoded_str = encode( { _ldaptype = string.format("%X", asn1_type), data } )
  return encoded_str
end


--- Attempts to bind to the server using the credentials given
--
-- @param socket socket already connected to the ldap server
-- @param params table containing <code>version</code>, <code>username</code> and <code>password</code>
-- @return success true or false
-- @return err string containing error message
function _M.bindRequest( socket, params )

  local catch = function() socket:close() stdnse.debug1("bindRequest failed") end
  local try = nmap.new_try(catch)
  local ldapAuth = encode( { _ldaptype = 80, params.password } )
  local bindReq = encode( params.version ) .. encode( params.username ) .. ldapAuth
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
  try( socket:send( packet ) )
  packet = try( socket:receive() )

  pos, packet_len = decoder.decodeLength( packet, 2 )
  pos, response.messageID = decode( packet, pos )
  pos, tmp = bin.unpack("C", packet, pos)
  pos, len = decoder.decodeLength( packet, pos )
  response.protocolOp = asn1.intToBER( tmp )

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

--- Performs an LDAP Unbind
--
-- @param socket socket already connected to the ldap server
-- @return success true or false
-- @return err string containing error message
function _M.unbindRequest( socket )

  local ldapMsg, packet
  local catch = function() socket:close() stdnse.debug1("bindRequest failed") end
  local try = nmap.new_try(catch)

  local encoder = asn1.ASN1Encoder:new()
  encoder:registerTagEncoders(tagEncoder)

  ldapMessageId = ldapMessageId +1
  ldapMsg = encode( ldapMessageId ) .. encodeLDAPOp( APPNO.UnbindRequest, false, nil)
  packet = encoder:encodeSeq( ldapMsg )
  try( socket:send( packet ) )
  return true, ""
end

return _M;