
protected Crypto.RSA.State key;
protected string keyId;
protected Standards.URI endpoint;
protected string login;

protected int query_size = 256;

constant CACHE_TIMEOUT = 60; // 1 minute

Protocols.HTTP.Session session = Protocols.HTTP.Session();
Cache.cache exist_cache = Cache.cache(Cache.Storage.Memory(), Cache.Policy.Timed(CACHE_TIMEOUT));
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
    else if(status >= 400) handle_error(d);
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
    else if(status >= 400) handle_error(d);
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
mixed get_object(string path) {
    Standards.URI op = Standards.URI(endpoint); 
    op->path = "/" + login + "/" + path;
	
	mapping h = Public.Storage.Manta.generate_authorization_header(keyId, key);
	
    mixed d = session->do_method_url("GET", (string)op, 0, 0, h)->wait();
	
	int status = d->status();
	
    if(status == 200) return d; // success!
    else if(status >= 400) handle_error(d);
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
    else if(status >= 400) handle_error(d);
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
    else if(status >= 400) handle_error(d);
	else return 0;	
}

int is_directory(string path) {
	mixed obj;
obj = head_object(path);
//	if(catch(obj = head_object(path)))
//		return 0;
	if(get_content_type(obj) == "application/x-json-stream" && 
		get_content_subtype(obj) == "directory") return 1;
		else return 0;
}

int exists(string path) {
	mixed obj;
	if(catch(obj = head_object(path)))
		return 0;
	return 1;
}

protected mixed head_object(string path) {
    Standards.URI op = Standards.URI(endpoint); 
    op->path = "/" + login + "/" + path;
	
	mapping h = Public.Storage.Manta.generate_authorization_header(keyId, key);
	
   mixed d = session->do_method_url("HEAD", (string)op, 0, 0, h);
//    mixed d = Protocols.HTTP.do_method("HEAD", (string)op, 0, h);
	
	int status = d->status();
	
    if(status == 200) return d; // success!
	//else if(status == 404) throw(Error.Generic("Not found\n"));
    else if(status >= 400) handle_error(d);
	else return 0;	
}

protected ADT.List get_paged_result(Standards.URI uri, int|void max, mixed|void current, ADT.List|void list) {
//	werror("get_paged_result(%O, %O, %O, %O)\n", uri, max, current, list);
    mapping v = (["limit": query_size]);
    
    uri->query="limit=" + query_size;
	if(current) uri->query += ("&marker=" + current);

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
			if(current && !r && sizeof(list)) continue; // skip the first row on continuation queries. 
			current = row->name;
            list->append(row);
         }
		
		 if(sizeof(list) < total)
		 {
			 list = get_paged_result(uri, max, current, list);
		 }
		 
         return list;
     }
     else if(status >= 400) handle_error(d);
}

protected string get_content_type(object query) {
  string ct = query->headers()["content-type"];
  if(!ct) return "";
  
  return String.trim_whites((ct/";")[0]);
}

protected string get_content_subtype(object query) {
  string ct = query->headers()["content-type"];
  if(!ct) return "";

  array c = ct/";";
  if(sizeof(c) < 2) return "";
  
  ct = String.trim_whites(c[1]);
  if(!has_prefix(ct, "type")) return "";
  return String.trim_whites((ct/"=")[1]);
}

protected void handle_error(object d) {
  int status = d->status();
  if(has_prefix(d->con->request, "HEAD ")) // HEAD responses have no body, so don't try to read it.
  {
    switch(status) {
      case 400:
        throw(.Error.BadRequestError("Response code " + status + "\n"));
        break;
      case 403:
        throw(.Error.AuthorizationError("Response code " + status + "\n"));
        break;
      case 404:
        throw(.Error.ResourceNotFoundError("Response code " + status + "\n"));
        break;
      case 406:
        throw(.Error.NotAcceptableError("Response code " + status + "\n"));
        break;
      case 412:
        throw(.Error.PreconditionFailedError("Response code " + status + "\n"));
        break;
      case 503:
        throw(.Error.ServiceUnavailableError("Response code " + status + "\n"));
        break;
      default:
       throw(.Error.MantaError("Response code " + status + "\n"));		 
        break;
    } 
  }
  
  string ct = get_content_type(d);
  if(ct != "application/json")
    throw(.Error.MantaError("Invalid response content-type: " + ct + "\n"));		 
  mixed res = Standards.JSON.decode(d->data());
  
  program ep = .Error[res->code + "Error"];
  if(!ep) ep = .Error.MantaError;
  throw(ep(res->message + "\n"));
}