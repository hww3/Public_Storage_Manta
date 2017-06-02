string type;
array(string) assets;
string exec;
string init;
int count = 1;
int memory = 256;
int disk = 2;

string encode_json(mixed ... args) {
mapping m = (mapping)this;
//werror("encode_json %O\n", m);

  if(!type) m_delete(m, "type");
  if(!assets) m_delete(m, "assets");
  if(!init) m_delete(m, "init");
  m_delete(m, "encode_json");
  return Standards.JSON.encode(m);
}

protected mixed cast(string type) {
  if(type == "mapping")
    return mkmapping(indices(this), values(this));
  else throw(Error.Generic("Cannot cast JobPhase to type " + type + ".\n"));    
}