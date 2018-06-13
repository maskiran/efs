#!/usr/bin/env python

import fuse
import json
import log
import os
import rest_client
import stat
import sys
import time
import threading


fuse.fuse_python_api = (0, 2)


logger = log.setup_logging("/tmp/efs")

READ_CACHE = {}
WRITE_CACHE = {}
SYMLINK_FILES = {}


def embed_shell():
  import IPython; IPython.embed()


class EFSStat(fuse.Stat):
  def __init__(self):
    self.st_mode = 0
    self.st_ino = 0
    self.st_dev = 0
    self.st_nlink = 0
    self.st_uid = 0
    self.st_gid = 0
    self.st_size = 0
    self.st_atime = 0
    self.st_mtime = 0
    self.st_ctime = 0


def load_entity_types():
  """
  Load the json config file by removing all the comments and return
  the json data.
  """
  data = []
  dir_name = os.path.dirname(__file__)
  fname = os.path.join(dir_name, 'entity_types.json')
  with open(fname) as fd:
    for line in fd:
      line = line.lstrip()
      if line.startswith("//") or line.startswith("#"):
        continue
      data.append(line)
  json_data = json.loads("\n".join(data))
  return json_data


class EFS(fuse.Fuse):
  """
  Entity file system.
  /<entity-type/
  /<entity-type/entity-name
  """

  def __init__(self, *args, **kwargs):
    fuse.Fuse.__init__(self, *args, **kwargs)
    self.parser.add_option('--ip', help='Rest IP Address')
    self.parser.add_option('--user', help='Rest Username')
    self.parser.add_option('--password', help='Rest Password')
    self.parser.add_option('--cfg', help=('Get Rest info from this file '
                                          'instead of providing on the '
                                          'command line '
                                          '(sample file mnt_cfg.json)'))
    self.parse()
    self.options = self.cmdline[0]
    if self.options.cfg is not None:
      self.load_mount_config_file(self.options.cfg)
    # set direct_io option
    self.fuse_args.add('direct_io')
    self.rest = rest_client.RestClient(
                  self.options.ip, self.options.user,
                  self.options.password)
    self.entity_types = load_entity_types()
    # start a thread to refresh the auth cookie
    # self.reconnect_thread()

  def load_mount_config_file(self, file_path):
    """
    Load the config file that has information and set the options
    variables
    """
    with open(file_path) as fd:
      data = json.load(fd)
      self.options.ip = data['ip']
      self.options.user = data['user']
      self.options.password = data['password']

  def reconnect_thread(self):
    t = threading.Timer(300, rest_client.RestClient,
                        [self.options.ip, self.options.user,
                         self.options.password])
    t.start()

  def get_entity_type_and_name(self, path):
    # FUSE path is always absolute from the mount point
    # remove the first slash
    path = path[1:]
    cmps = path.split("/")
    if len(cmps) == 1:
      entity_type = cmps[0]
      entity_name = ""
    elif len(cmps) == 2:
      entity_type = cmps[0]
      entity_name = cmps[1]
    return (entity_type, entity_name)

  def getattr(self, path):
    logger.info("getattr path %s", path)
    st = EFSStat()
    entity_type, entity_name = self.get_entity_type_and_name(path)
    if entity_type == "" or entity_name == "":
      # root of the mountpoint or first level (entity_type only)
      st.st_mode = stat.S_IFDIR | 0755
      st.st_nlink = 2
    else:
      # check if path is symlink
      if path in SYMLINK_FILES:
        logger.info('path is symlink', path)
        st.st_mode = stat.S_IFLNK | 0777
      else:
        st.st_mode = stat.S_IFREG | 0666
      st.st_nlink = 1
    return st

  def readdir(self, path, offset):
    # delete all keys in SYMLINK_FILES
    for key in SYMLINK_FILES.keys():
      del SYMLINK_FILES[key]
    logger.info("readdir path %s", path)
    if path == "/":
      flist = ['.', '..'] + self.entity_types.keys()
      for f in flist:
        yield fuse.Direntry(str(f))
    else:
      entity_type, entity_name = self.get_entity_type_and_name(path)
      rsp = self.rest.get(entity_type).json()
      if 'entities' in rsp:
        entities = rsp['entities']
      else:
        entities = rsp
      for entity in entities:
        id_attr = self.entity_types[entity_type]['id']
        yield fuse.Direntry(str(entity[id_attr]))
        display_attr = self.entity_types[entity_type].get('display')
        if display_attr and id_attr != display_attr:
          SYMLINK_FILES[os.path.join(path, str(entity[display_attr]))] = str(entity[id_attr])
          yield fuse.Direntry(str(entity[display_attr]))

  def readlink(self, path):
    logger.info("readlink %s", path)
    return SYMLINK_FILES[path]

  def open(self, path, flags):
    logger.info("open path %s flags %s", path, flags)
    entity_type, entity_id = self.get_entity_type_and_name(path)
    id_attr = self.entity_types[entity_type]['id']
    if self.entity_types[entity_type].get("accessible_by_id", True):
      rsp = self.rest.get(entity_type, entity_id)
      if rsp.ok:
        entity = rsp.json()
      else:
        # may be new file is being created. so send the create
        # properties
        entity = self.entity_types[entity_type].get("create_properties", {})
        if 'name' in entity:
          # entity_id is the name of the new item here
          entity['name'] = entity_id
          if entity_type == "containers":
            # set the storagePoolId
            s_rsp = self.rest.get("storage_pools").json()
            s_ids = [str(s['id']) for s in s_rsp['entities']]
            entity['storagePoolId'] = ",".join(s_ids)
    else:
      # individual entity cannot be obtained
      logger.error('individual entity cannot be obtained')
      logger.info("%s, %s, %s", entity_type, id_attr, entity_id)
      entity = self.rest.get_matching_entity(
                  entity_type, id_attr, entity_id)
    if entity:
      text = json.dumps(entity, indent=2) + "\n"
      READ_CACHE[path] = text
    return

  def read(self, path, size, offset):
    logger.info("read path %s, offset %d, size %d", path, offset, size)
    slen = 0
    buf = ""
    if path in READ_CACHE:
      slen = len(READ_CACHE[path])
    if offset < slen:
      if (offset + size) > slen:
        size = slen - offset
      if path in READ_CACHE:
        buf = READ_CACHE[path][offset:offset+size]
        logger.info('returning from %d to %d', offset, offset+size)
    else:
      logger.info('EOF')
      return 0
    return str(buf)

  def release(self, path, flags):
    logger.info("release path %s %s", path, flags)
    if path in READ_CACHE:
      del READ_CACHE[path]
    if path in WRITE_CACHE:
      del WRITE_CACHE[path]
    return 0

  def mknod(self, path, *args):
    logger.info("mknod path %s %s", path, str(args))

  def chmod(self, path, *args):
    logger.info("chmod path %s %s", path, str(args))

  def chown(self, path, *args):
    logger.info("chown path %s %s", path, str(args))

  def utime(self, path, *args):
    logger.info("utime path %s %s", path, str(args))

  def truncate(self, path, *args):
    if path in WRITE_CACHE:
      WRITE_CACHE[path] = ""
    logger.info("truncate path %s %s", path, str(args))

  def create(self, path, *args):
    logger.info("create path %s %s", path, str(args))

  def write(self, path, buf, offset):
    logger.info("write path %s", path)
    logger.info(buf)
    if path not in WRITE_CACHE:
      WRITE_CACHE[path] = ""
    WRITE_CACHE[path] += buf
    return len(buf)

  def flush(self, path):
    logger.info("flush path %s", path)
    if path in WRITE_CACHE:
      logger.info('flush data %s', WRITE_CACHE[path])
      # when a file is written, it has to be POSTed. Delete the last
      # part of the path, as thats the name of the entity and its
      # already in the content
      content = WRITE_CACHE[path]
      data = json.loads(content)
      entity_type, entity_name = self.get_entity_type_and_name(path)
      # only write the content thats creatable
      cprops = self.entity_types[entity_type].get("create_properties", {})
      # delete all the props from data that are not in create_properties
      for prop in data.keys():
        if prop not in cprops:
          del data[prop]
      # in the path, entity_name is the name and not the id.
      # if data has name attribute, replace that with the file name
      if 'name' in data:
        data['name'] = entity_name
      rsp = self.rest.post(entity_type, data)
      logger.info(rsp.text)
      del WRITE_CACHE[path]
      if not rsp.ok:
        return -1

  def unlink(self, path):
    logger.info("unlink %s", path)
    if path in SYMLINK_FILES:
      target = SYMLINK_FILES[path]
      path = os.path.join(os.path.dirname(path), target)
      logger.info("unlink the target %s", path)
    rsp = self.rest.delete(path)
    if rsp.ok:
      if path in READ_CACHE:
        del READ_CACHE[path]
      if path in WRITE_CACHE:
        del WRITE_CACHE[path]
      return 0
    return -1


def main():
  usage  = fuse.Fuse.fusage
  server = EFS(version="%prog " + fuse.__version__,
               usage=usage, dash_s_do='setsingle')

  #import IPython; IPython.embed()
  try:
    server.main()
  except Exception as e:
    logger.exception(e)
    raise e

if __name__ == '__main__':
  main()
