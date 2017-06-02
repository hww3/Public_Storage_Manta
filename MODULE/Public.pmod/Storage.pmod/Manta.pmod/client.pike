
protected Crypto.RSA.State key;
protected string keyId;
protected Standards.URI endpoint;
protected string login;

protected int query_size = 256;

Protocols.HTTP.Session session = Protocols.HTTP.Session();

//! @param private_key
//!   a string containing the contents of an SSH private key file (RSA)
//!
//! @param public_key
//!   a string containing the contents of an SSH public key file (RSA)
void create(string url, string username, string private_key, string public_key, string private_key_pass) {
   endpoint = Standards.URI(url);
   login = username;
   key = Public.Storage.Manta.load_ssh_private_key(private_key, private_key_pass);
   keyId = "/" + login + "/keys/" + Public.Storage.Manta.generate_fingerprint(public_key);
}

//!
int put_directory(string directory) {
    Standards.URI op = Standards.URI(endpoint); 
    op->path = "/" + login + "/" + directory;
	
	mapping h = Public.Storage.Manta.generate_authorization_header(keyId, key);
	h["content-type"] = "application/json; type=directory";
	
    mixed d = session->do_method_url("PUT", (string)op, 0, 0, h)->wait();
	
	int status = d->status();
	
    if(status == 204) return 1; // success!
    else if(status >= 400) {
        string ct = get_content_type(d);
        if(ct != "application/json")
          throw(Error.Generic("Invalid response content-type: " + ct + "\n"));		 
       mixed res = Standards.JSON.decode(d->data());
       throw(Error.Generic(status + " " + res->message + "\n"));
    }
	else return 0;	
}

//!
function(string:int) delete_object = delete_directory;

//!
int delete_directory(string directory) {
    Standards.URI op = Standards.URI(endpoint); 
    op->path = "/" + login + "/" + directory;
	
	mapping h = Public.Storage.Manta.generate_authorization_header(keyId, key);
	h["content-type"] = "application/json; type=directory";

    mixed d = session->do_method_url("DELETE", (string)op, 0, 0, h)->wait();
	
	int status = d->status();
	
    if(status == 204) return 1; // success!
    else if(status >= 400) {
        string ct = get_content_type(d);
        if(ct != "application/json")
          throw(Error.Generic("Invalid response content-type: " + ct + "\n"));		 
       mixed res = Standards.JSON.decode(d->data());
       throw(Error.Generic(status + " " + res->message + "\n"));
    }
	else return 0;	
}


//!
mixed list_directory(string directory) {
   Standards.URI op = Standards.URI(endpoint); 
   op->path = "/" + login + "/" + directory;
   mixed r = get_paged_result(op);
   return (array)r;
}

//!
mixed get_object(string path, string content) {
    Standards.URI op = Standards.URI(endpoint); 
    op->path = "/" + login + "/" + path;
	
	mapping h = Public.Storage.Manta.generate_authorization_header(keyId, key);
	
    mixed d = session->do_method_url("GET", (string)op, 0, 0, h)->wait();
	
	int status = d->status();
	
    if(status == 200) return d; // success!
    else if(status >= 400) {
        string ct = get_content_type(d);
        if(ct != "application/json")
          throw(Error.Generic("Invalid response content-type: " + ct + "\n"));		 
       mixed res = Standards.JSON.decode(d->data());
       throw(Error.Generic(status + " " + res->message + "\n"));
    }
	else return 0;	
}


//!
int put_object(string path, string content, string content_type, void|mapping headers) {
    Standards.URI op = Standards.URI(endpoint); 
    op->path = "/" + login + "/" + path;
	
	mapping h = Public.Storage.Manta.generate_authorization_header(keyId, key);
	if(content_type) 
	  h["content-type"] = content_type;
	 h["content-MD5"] = MIME.encode_base64(Crypto.MD5.hash(content));
	
	if(headers) {
		h = headers + h;
 	}
    mixed d = session->do_method_url("PUT", (string)op, 0, content, h)->wait();
	
	int status = d->status();
	
    if(status == 204) return 1; // success!
    else if(status >= 400) {
        string ct = get_content_type(d);
        if(ct != "application/json")
          throw(Error.Generic("Invalid response content-type: " + ct + "\n"));		 
       mixed res = Standards.JSON.decode(d->data());
       throw(Error.Generic(status + " " + res->message + "\n"));
    }
	else return 0;	
}

//!
int put_snaplink(string destPath, string srcPath) {
    Standards.URI op = Standards.URI(endpoint); 
    op->path = "/" + login + "/" + destPath;
	
	mapping h = Public.Storage.Manta.generate_authorization_header(keyId, key);

    h["location"] = "/" + login + "/" + srcPath;	
    h["content-type"] = "application/json; type=link";
    mixed d = session->do_method_url("PUT", (string)op, 0, 0, h)->wait();
	
	int status = d->status();
	
    if(status == 204) return 1; // success!
    else if(status >= 400) {
        string ct = get_content_type(d);
        if(ct != "application/json")
          throw(Error.Generic("Invalid response content-type: " + ct + "\n"));		 
       mixed res = Standards.JSON.decode(d->data());
       throw(Error.Generic(status + " " + res->message + "\n"));
    }
	else return 0;	
}


protected ADT.List get_paged_result(Standards.URI uri, int|void max, mixed|void current, ADT.List|void list) {
//	werror("get_paged_result(%O, %O, %O, %O)\n", uri, max, current, list);
    mapping v = (["limit": query_size]);
    
    uri->query="limit=" + query_size;
	if(current) uri->query += ("&marker=" + current);
//	werror("uri: " + (string)uri + "\n");
    mixed d = session->do_method_url("GET", (string)uri, 0, 0,Public.Storage.Manta.generate_authorization_header(keyId, key))->wait();

    if(!list) list = ADT.List();

    int status = d->status();

    if(status == 200) {
        string ct = get_content_type(d);
        if(ct != "application/x-json-stream")
          throw(Error.Generic("Invalid response content-type: " + ct + "\n"));
         
         int total = (int)(d->headers()["result-set-size"]);
		 if(max && max < total) total = max;
		 
         foreach(d->data()/"\n"; int r; string j) {
         if(!sizeof(j)) continue;
            mixed row = Standards.JSON.decode(j);
			if(current && !r) continue; // skip the first row on continuation queries. 
			current = row->name;
			//werror("%O\n", row);
            list->append(row);
         }
//         werror("total: %O", d->headers["result-set-size"]);
		
		 if(sizeof(list) < total)
		 {
//			 werror("getting next page\n");
			 list = get_paged_result(uri, max, current, list);
		 }
		 
         return list;
     }
     else if(status >= 400) {
         string ct = get_content_type(d);
         if(ct != "application/json")
           throw(Error.Generic("Invalid response content-type: " + ct + "\n"));		 
        mixed res = Standards.JSON.decode(d->data());
        throw(Error.Generic(status + " " + res->message + "\n"));
     }

}

protected string get_content_type(object query) {
  string ct = query->headers()["content-type"];
  if(!ct) return "";
  
  return String.trim_whites((ct/";")[0]);
}