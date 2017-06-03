//! An entry from a directory listing
/* 
 ([ 
                  "mtime": "2013-05-22T17:39:43.714Z",
                  "name": "public",
                  "type": "directory"
                ])
*/

constant TIME_FORMAT = "%Y-%M-%DT%h:%m:%s.%f%z";

protected string name;
protected string parent;
protected string mtime;
protected string type;
protected Calendar.YMD mto;

protected void create(mapping ent, string _parent) {
  if(!(<"directory", "object">)[ent->type]) throw(Error.Generic("Entry must be of type 'object' or 'directory'.\n")); 
  name = ent->name;
  mtime = ent->mtime;
  parent = _parent;
  type = ent->type;
}

//!
string get_name() { return name; }

//!
Calendar.YMD get_mtime() { if(!mto) return (mto = Calendar.parse(TIME_FORMAT, mtime)); else return mto; }

//!
string get_parent() { return parent; }

//!
int is_obj() { return type == "object"; }

//!
int is_dir() { return type == "directory"; }

string _sprintf(int i, void | mapping(string:int)m) { return "Entry(" + type + ":" +  parent + "/" + name + ")";}