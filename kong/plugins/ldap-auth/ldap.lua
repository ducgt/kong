local asn1 = require "kong.plugins.ldap-auth.asn1"
local bpack = string.pack
local bunpack = string.unpack

local _M = {}

local ldapMessageId = 1

local ERROR_MSG = {
  [1]  = "Initialization of LDAP library failed.",
  [4]  = "Size limit exceeded.",
  [13] = "Confidentiality required",
  [32] = "No such object",
  [34] = "Invalid DN",
  [49] = "The supplied credential is invalid."
}

local APPNO = {
  BindRequest = 0,
  BindResponse = 1,
  UnbindRequest = 2,
  ExtendedRequest = 23,
  ExtendedResponse = 24
}

local tagEncoder = {

  ['table'] = function(self, val)
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
}

local function encode(val)
  local encoder = asn1.ASN1Encoder:new()
  local encValue
  encoder:registerTagEncoders(tagEncoder)
  encValue = encoder:encode(val)
  if encValue then
    return encValue
  end

  return ''
end

local tagDecoder = {
  ["0A"] = function(self, encStr, elen, pos)
    return self.decodeInt(encStr, elen, pos)
  end,

  ["8A"] = function(self, encStr, elen, pos)
    return bunpack(encStr, "A" .. elen, pos)
  end,

  ["31"] = function(self, encStr, elen, pos)
    return pos, nil
  end
}

local function decode(encStr, pos)
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

function encodeLDAPOp(appno, isConstructed, data)
  local encoded_str = ""
  local asn1_type = asn1.BERtoInt(asn1.BERCLASS.Application, isConstructed, appno)
  encoded_str = encode({ _ldaptype = string.format("%X", asn1_type), data })
  return encoded_str
end

local function claculate_payload_length(encStr, pos, socket)
  local elen
  pos, elen = bunpack(encStr, 'C', pos)
  if (elen > 128) then
    elen = elen - 128
    local elenCalc = 0
    local elenNext
    for i = 1, elen do
      elenCalc = elenCalc * 256
      encStr = encStr..socket:receive(1)
      pos, elenNext = bunpack(encStr, 'C', pos)
      elenCalc = elenCalc + elenNext
    end
    elen = elenCalc
  end
  return pos, elen
end

function _M.bind_request(socket, username, password)
  local ldapAuth = encode({ _ldaptype = 80, password })
  local bindReq = encode(3) .. encode(username) .. ldapAuth
  local ldapMsg = encode(ldapMessageId) .. encodeLDAPOp(APPNO.BindRequest, true, bindReq)
  local packet
  local pos, packet_len, resultCode, tmp, len, _
  local response = {}
  local encoder = asn1.ASN1Encoder:new()
  local decoder = asn1.ASN1Decoder:new()

  encoder:registerTagEncoders(tagEncoder)
  decoder:registerTagDecoders(tagDecoder)

  packet = encoder:encodeSeq(ldapMsg)
  ldapMessageId = ldapMessageId +1
  socket:send(packet)
  packet = socket:receive(2)
  pos, packet_len = claculate_payload_length(packet, 2, socket)

  packet = socket:receive(packet_len)
  pos, response.messageID = decode(packet, 1)
  pos, tmp = bunpack(packet, "C", pos)
  pos, len = decoder.decodeLength(packet, pos)
  response.protocolOp = asn1.intToBER(tmp)

  if response.protocolOp.number ~= APPNO.BindResponse then
    return false, string.format("Received incorrect Op in packet: %d, expected %d", response.protocolOp.number, APPNO.BindResponse)
  end

  pos, response.resultCode = decode(packet, pos)

  if (response.resultCode ~= 0) then
    local error_msg
    pos, response.matchedDN = decode(packet, pos)
    pos, response.errorMessage = decode(packet, pos)
    error_msg = ERROR_MSG[response.resultCode]
    return false, string.format("\n  Error: %s\n  Details: %s",
      error_msg or "Unknown error occurred (code: " .. response.resultCode ..
      ")", response.errorMessage or "")
  else
    return true
  end
end


function _M.unbind_request(socket)

  local ldapMsg, packet

  local encoder = asn1.ASN1Encoder:new()
  encoder:registerTagEncoders(tagEncoder)

  ldapMessageId = ldapMessageId +1
  ldapMsg = encode(ldapMessageId) .. encodeLDAPOp(APPNO.UnbindRequest, false, nil)
  packet = encoder:encodeSeq(ldapMsg)
  socket:send(packet)
  return true, ""
end

function _M.start_tls(socket)

  local ldapMsg, pos, packet_len, resultCode, tmp, len, _
  local response = {}
  local encoder = asn1.ASN1Encoder:new()
  local decoder = asn1.ASN1Decoder:new()

  encoder:registerTagEncoders(tagEncoder)
  decoder:registerTagDecoders(tagDecoder)

  local method_name = encode({_ldaptype = 80, "1.3.6.1.4.1.1466.20037"})
  ldapMessageId = ldapMessageId +1
  ldapMsg = encode(ldapMessageId) .. encodeLDAPOp(APPNO.ExtendedRequest, true, method_name)
  packet = encoder:encodeSeq(ldapMsg)
  socket:send(packet)
  packet = socket:receive(2)
  pos, packet_len = claculate_payload_length(packet, 2, socket)

  packet = socket:receive(packet_len)
  pos, response.messageID = decode(packet, 1)
  pos, tmp = bunpack(packet, "C", pos)
  pos, len = decoder.decodeLength(packet, pos)
  response.protocolOp = asn1.intToBER(tmp)

  if response.protocolOp.number ~= APPNO.ExtendedResponse then
    return false, string.format("Received incorrect Op in packet: %d, expected %d", response.protocolOp.number, APPNO.ExtendedResponse)
  end

  pos, response.resultCode = decode(packet, pos)

  if (response.resultCode ~= 0) then
    local error_msg
    pos, response.matchedDN = decode(packet, pos)
    pos, response.errorMessage = decode(packet, pos)
    error_msg = ERROR_MSG[response.resultCode]
    return false, string.format("\n  Error: %s\n  Details: %s",
      error_msg or "Unknown error occurred (code: " .. response.resultCode ..
      ")", response.errorMessage or "")
  else
    return true
  end
end

return _M;
