#pike __REAL_VERSION__

//! Implements an abstraction of a Manta object store.

inherit Filesystem.Base;

protected Filesystem.Base parent; // parent filesystem

protected .client client;
protected string root = ""; // Note: Can now include leading "/"
protected string wd;        // never trailing "/"

//! @decl void create(.client manta_client, void|string directory, void|string root, void|int fast, void|Filesystem.Base parent)
//! Instanciate a new object representing the Manta object store.
//! @param manta_client
//! The Manta object store client to access
//! @param directory
//! The directory (in the real filesystem) that should become
//! the root of the filesystemobject.
//! @param root
//! Internal
//! @param fast
//! Internal
//! @param parent
//! Internal
protected void create(.client manta_client, void|string directory,  // default: cwd
		   void|string _root,   // internal: root
		   void|int fast,       // internal: fast mode (no check)
		   void|Filesystem.Base _parent)
   				 // internal: parent filesystem
{
  client = manta_client;
  if( _root )
  {
    sscanf(reverse(_root), "%*[/]%s", root);
    root = reverse( root ); // do not remove leading '/':es.
  }

  if(!fast)
  {
    if(!directory || directory=="" || directory[0]!='/')
      directory = combine_path("/", directory||manta_client->get_login());

    while( sizeof(directory) && directory[0] == '/' )
      directory = directory[1..];
    while( sizeof(directory) && directory[-1] == '/' )
      directory = directory[..<1];

      if(!(client->is_directory(combine_path("/",root,directory))))
	error("Not a directory\n");
  }
  while( sizeof(directory) && directory[0] == '/' )
    directory = directory[1..];
  while( sizeof(directory) && directory[-1] == '/' )
    directory = directory[..<1];
  wd = directory;
}

protected string _sprintf(int t)
{
  return t=='O' && sprintf("%O(/* root=%O, wd=%O */)", this_program, root, wd);
}

Filesystem.Base cd(string directory)
{
  if(isdir(directory)) // stay
    return this_program(client, combine_path(wd, directory),
			root, 1, parent);
  else return 0;
}

Filesystem.Base cdup()
{
  return cd("..");
}

string cwd()
{
  return wd;
}

Filesystem.Base chroot(void|string directory)
{
  if(directory)
  {
    Filesystem.Base new = cd(directory);
    if(!new) return 0;
    return new->chroot();
  }
  return this_program(client, "", combine_path("/",root,wd), 1, parent);
}

protected int isdir(string file)
{
   string full = combine_path(wd, file);
   if ( full!="" && full[0]=='/') full=full[1..];

   return client->is_directory(combine_path("/",root,full));
}

Filesystem.Stat stat(string file, int|void lstat)
{
   Stdio.Stat a;

   string full = combine_path(wd, file);
   if ( full!="" && full[0]=='/') full=full[1..];

   if((a = file_stat(combine_path("/",root,full), lstat)))
   {
     Filesystem.Stat s = Filesystem.Stat();
     s->fullpath = sprintf("/%s", full);
     s->name = file;
     s->filesystem = this;
     s->attach_statobject(a);
     return s;
   }
   else
     return 0;
}

array(string) get_dir(void|string directory, void|string|array(string) globs)
{
  directory = directory ? combine_path(wd, directory) : wd;

  array(.Entry) y = client->list_directory(combine_path("/",root,directory));
  if(!globs)
    return y->get_name();
  else if(stringp(globs))
    return glob(globs, y->get_name());
  else
  {
    array(string) p = ({});
    foreach(globs, string g)
    {
      array(string) z;
      p += (z = glob(g, y->get_name()));
      y -= z;
    }
    return p;
  }
}

array(Filesystem.Stat) get_stats(void|string directory,
				 void|string|array(string) globs)
{
  Filesystem.Base z = this;

  if(directory &&
     !(z = z->cd(directory)))
    return 0;

  array(string) a = z->get_dir("", globs);
  if(!a) return 0;

  return map(a, z->stat, 1)-({0});
}

Stdio.File open(string filename, string mode)
{
  filename = combine_path(wd, filename);
  if ( filename!="" && filename[0]=='/') filename=filename[1..];
  
  mixed r;

  Stdio.File f;
  mode = mode||"rw";
  if(mode != mode - "r") {
    if(catch(r = client->get_object(combine_path("/",root,filename) )))
      return 0;
    f = .File(client, filename, r->headers()["content-type"], r->data(), mode);
  } else f = .File(client, filename, 0, 0, mode);
  
  return f;
}

// int access(string filename, string mode)
// {
//   return 1; // sure
// }

int rm(string filename)
{
  filename = combine_path(wd, filename);
  return client->delete_object(combine_path("/",root,filename));
}

void chmod(string filename, int|string mode)
{
  error("chown not supported\n");
}

void chown(string filename, int|object owner, int|object group)
{
  error("chown not supported\n");
}

array find(void|function(Filesystem.Stat, mixed|void...:int) mask,
	   mixed|void ... extra)
{
  array(Filesystem.Stat) res = ({});
  array(Filesystem.Stat) d = get_stats() || ({});
  array(Filesystem.Stat) r = filter(d, "isdir");

  if(mask)
    res += filter(d-r, mask, @extra);
  else
    res += d-r;

  foreach(r, Filesystem.Stat dir)
  {
    if(!mask || mask(dir, @extra))
      res += ({ dir });

    if(dir->name=="." || dir->name=="..")
      continue;
    res += dir->cd()->find(mask, @extra);
  }

  return res;
}
