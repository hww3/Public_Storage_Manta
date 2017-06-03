inherit Stdio.FakeFile;

protected .client client;
protected string p;
protected string ct = "application/octet-stream";

//!
protected void create(.client manta_client, string path, string|void content_type, string|void data, string|void mode, int|void ptr) {
  client = manta_client;
  p = path;
  if(content_type) ct = content_type;
  if(!data) data = "";
  ::create(data, mode, ptr);
}

this_program dup() {
  return this_program(client, p, ct, data, make_type_str(), ptr);
}

//!
int(-1..) write(string|array(string) str, mixed ... extra) {
  int res = ::write(str, @extra);
  werror("res: %O\n", res);
  client->put_object(combine_path("/", p), data, ct);
  return res;
}

//!
string get_content_type() { 
  return ct;
}  

//! 
void set_content_type(string content_type) {
  ct = content_type;
}
