//!

protected Crypto.RSA.State
parse_private_key(string key) {
Standards.ASN1.Types.Object a = Standards.ASN1.Decode.simple_der_decode(key);

  if (!a || (a->type_name != "SEQUENCE"))
    throw(Error.Generic("Invalid key format\n"));
  return _parse_private_key([object(Standards.ASN1.Types.Sequence)]a);
}

protected Crypto.RSA.State _parse_private_key(Standards.ASN1.Types.Sequence seq)
{
  if ((sizeof(seq->elements) != 9)
      || (sizeof(seq->elements->type_name - ({ "INTEGER" })))
      || seq->elements[0]->value)
    throw(Error.Generic("Invalid internal key format\n"));
  
  Crypto.RSA.State rsa = Crypto.RSA();
  rsa->set_public_key(seq->elements[1]->value, seq->elements[2]->value);
  rsa->set_private_key(seq->elements[3]->value, seq->elements[4..]->value);
  return rsa;
}

//! parse a SSH private key file
//! @param contents
//!    the contents of an SSH private key file.
//! @returns
//!   the fingerprint of the public key.
object load_ssh_private_key(string contents, string|void password) {
  object part, rsa;
  string key;
  
  object msg = Standards.PEM.Messages(contents);
  part = msg->parts["RSA PRIVATE KEY"][0];
  if (!part || !(key = part->body))
    throw(Error.Generic("Private key not found\n"));
	if(part->headers["dek-info"] && part->headers["dek-info"] && search(part->headers["proc-type"], "ENCRYPTED") != -1)
	{
		key = Standards.PEM.decrypt_body(part->headers["dek-info"], key, password);
	}
  // Unclear why the identical code in Standards.PKCS doesn't work
  rsa = parse_private_key(key);
    if(!rsa) throw(Error.Generic("Private key not valid\n"));
  return rsa;
}

protected string generate_signature(Crypto.RSA.State private_key, string data) {
  return MIME.encode_base64(private_key->pkcs_sign(data, Crypto.SHA256));
}

//! generate an authorization header value using HTTP Signatures
//!
//!  @param keyId
//!    a string containing the keyId associated with the signature (this is implementation defined)
//!
//!  @param key
//!    an RSA private key
//!
//! @note
//!    this is a specific implementation that assumes RSA and SHA256 and a Date header.
//! @returns
//!   a string suitable for use in an HTTP authorization header.
mapping generate_authorization_header(string keyId, Crypto.RSA.State key, ) {
  string date = Calendar.now()->format_http();
  return ([ "authorization": sprintf("Signature keyId=\"%s\",algorithm=\"%s\",signature=\"%s\"",
               keyId, "rsa-sha256", (generate_signature(key, "date: " + date) - "\r\n")),
            "date": date 
            ]);
}

//! generate a fingerprint string from an SSH public key file
//! @param contents
//!    the contents of an SSH public key file.
//! @returns
//!   the fingerprint of the public key.
string generate_fingerprint(string contents) {
  if(!has_prefix(contents, "ssh-rsa")) throw(Error.Generic("Incorrect key type. Must begin with ssh-rsh.\n"));
  
  string key = ((contents/" ") - ({""}))[1];
  
  if(!key)  throw(Error.Generic("Incorrect key format.\n"));
  
  key = MIME.decode_base64(key);
  
  string fingerprint = Crypto.MD5.hash(key);
  return (sprintf("%{%x%}", (array)fingerprint)/2) * ":";
}
