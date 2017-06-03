protected string type;
protected array(string) assets;
protected string exec;
protected string init;
protected int count = 1;
protected int memory = 256;
protected int disk = 2;
protected string name;

//!
variant protected void create() {
}

//!
variant protected void create(string _exec, string|void _init) {
	this::exec = exec;
	this::init = init;
}

//!
variant protected void create(mapping vals) {
	function f;

	// so bad
	foreach(vals; string k; mixed v)
	  if((f = this["set_" + k]))
		   f(v);
}

protected string _sprintf(int i, void | mapping(string:int)m) { return "JobPhase(exec=" +  exec  +")"; }

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

//!
//! @param init
//!   commands that will be run before job
void set_init(string init) {
	this::init = init;
}

//!
//! @param exec
//!   commands that will be run as part of job
void set_exec(string exec) {
	this::exec = exec;
}

//! set paths of objects that will be copied into the execution context
//!
//! @note
//!  all paths are relative to the user's account root.
void set_assets(array(string) paths) {
	this::assets = paths;
}

//!
void set_memory(int mb) {
	this::memory = mb;
}

//!
void set_disk(int gb) {
	// TODO param checking
	
	this::disk = gb;
}

//!
void set_count(int count) {
	this::count = count;
}

//!
void set_type(string type) {
	if(!(<"map", "reduce">)[type]) error("type must be either 'map' or 'reduce'.\n");
	this::type = type;
}

//!
void set_name(string name) {
	this::name = name;
}