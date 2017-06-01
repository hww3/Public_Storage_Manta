
protected Crypto.RSA.State key;
protected string keyId;
protected Standards.URI endpoint;
protected string login;

protected int query_size = 256;

//! @param private_key
//!   a string containing the contents of an SSH private key file (RSA)
//!
//! @param public_key
//!   a string containing the contents of an SSH public key file (RSA)
void create(string url, string username, string private_key, string public_key) {
   endpoint = Standards.URI(url);
   login = username;
   key = Public.Storage.Manta.load_ssh_private_key(private_key);
   keyId = "/" + login + "/keys/" + Public.Storage.Manta.generate_fingerprint(public_key);
}


mixed list_directory(string directory) {
   Standards.URI op = Standards.URI(endpoint); 
   op->path = "/" + login + "/" + directory;
   mixed d = Protocols.HTTP.get_url(op, (["limit": query_size]), Public.Storage.Manta.generate_authorization_header(keyId, key));
   
   if(d->status == 200) {
       string ct = get_content_type(d);
       if(ct != "application/x-json-stream")
         throw(Error.Generic("Invalid response content-type: " + ct + "\n"));
         
        array x = allocate((int)(d->headers["result-set-size"])); 
        
        foreach(d->data()/"\n"; int r; string j) {
        if(!sizeof(j)) continue;
           mixed row = Standards.JSON.decode(j);
           x[r] = row->name;
        }
        
        return x;
    }
    else if(d->status == 403) {
       throw(Error.Generic("Forbidden. Invalid Credentials?\n"));
    }
   return 0;
}


protected string get_content_type(object query) {
  string ct = query->headers["content-type"];
  if(!ct) return "";
  
  return String.trim_whites((ct/";")[0]);
}