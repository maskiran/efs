import httplib
import json
import logging
import pprint
import requests
import requests.packages.urllib3
import time

try:
  requests.packages.urllib3.disable_warnings()
except AttributeError:
  pass


logger = logging.getLogger('efs.rest')


# chunked encoding of some data from causes IncompleteRead
# exception by the requests (httplib). So patch the read to return the
# data that was read
def patch_http_response_read(func):
    def inner(*args):
        try:
            return func(*args)
        except httplib.IncompleteRead, e:
            return e.partial

    return inner

httplib.HTTPResponse.read = patch_http_response_read(httplib.HTTPResponse.read)


def retry(old_func):
  """
  Retry on timeout exceptions, with a sleep of 5 seconds between each
  try
  """
  def inner(*args, **kwargs):
    count = 1
    while count <= 3:
      try:
        return old_func(*args, **kwargs)
      except requests.Timeout:
        time.sleep(5)
        count += 1
  return inner


class RestClient(object):
  def __init__(self, ip, user='admin', password='nutanix/4u',
               port=9440):
    self.ip = ip
    self.port = port
    self.user = user
    self.password = password
    self.url = ('https://%s:%d/services/rest/v1' %
                 (ip, port))
    self.session = self._get_server_session()

  def _get_server_session(self, user=None, password=None):
    if user is None:
      user = self.user
    if password is None:
      password = self.password
    session = requests.Session()
    session.auth = (user, password)
    return session

  @retry
  def post(self, entity_type, body=None, headers=None, **kwargs):
    if headers is None:
      headers = {}
    # body can be either the dict or passed as kwargs
    url = self._make_url(entity_type)
    if body is None:
      body = kwargs
    logger.info('POST %s', url)
    logger.info('Body %s', pprint.pformat(body))
    rsp = self.session.post(url, data=json.dumps(body), verify=False,
                            headers=headers)
    logger.info('Status: %d', rsp.status_code)
    if not rsp.ok:
      logger.error('Error in POST Response: %s', rsp.text)
    else:
      logger.debug('Response: %s', str(rsp.json()))
    return rsp

  @retry
  def put(self, entity_type, body=None, **kwargs):
    # body can be either the dict or passed as kwargs
    url = self._make_url(entity_type)
    if body is None:
      body = kwargs
    logger.info('PUT %s', url)
    logger.info('Body %s', pprint.pformat(body))
    rsp = self.session.put(url, data=json.dumps(body), verify=False)
    logger.info('Status: %d', rsp.status_code)
    if not rsp.ok:
      logger.error('Error in PUT Response: %s', rsp.text)
    else:
      logger.debug('Response: %s', str(rsp.json()))
    return rsp

  @retry
  def delete(self, entity_type, *args, **kwargs):
    # args are appended to the url as components
    # /arg1/arg2/arg3
    # kwargs are sent in the url as request params
    # ?arg1=val1&arg2=val2
    url = self._make_url(entity_type, *args)
    logger.info('DELETE %s', url)
    rsp = self.session.delete(url, params=kwargs, verify=False)
    logger.info('Status: %d', rsp.status_code)
    if not rsp.ok:
      logger.error('Error in DELETE Response: %s', rsp.text)
    else:
      logger.info('Response: %s', str(rsp.json()))
    return rsp

  @retry
  def get(self, entity_type, *args, **kwargs):
    # args are appended to the url as components
    # /arg1/arg2/arg3
    # kwargs are sent in the url as request params
    # ?arg1=val1&arg2=val2
    url = self._make_url(entity_type, *args)
    logger.info('GET %s', url)
    rsp = self.session.get(url, params=kwargs, verify=False)
    logger.info('Status: %d', rsp.status_code)
    if not rsp.ok:
      logger.error('Error in GET Response: %s', rsp.text)
    else:
      logger.debug('Response: %s', pprint.pformat(rsp.json()))
    return rsp

  @retry
  def get_entity_id_from_name(self, entity_type, name,
                              name_attribute='name',
                              id_attribute='id'):
    """
    Given a name attribute of a given entity_type, return the id of the
    given entity. The id is the 'id' attribute. A different attribute
    can be obtained by passing in the attribute_name
    """
    logger.info('Getting entity id from name for %s %s',
             entity_type, name)
    rsp = self.get(entity_type)
    if rsp.status_code:
      if 'entities' in rsp.json():
        entities = rsp.json()['entities']
      else:
        entities = rsp.json()
      for entity in entities:
        if entity[name_attribute] == name:
          val = entity[id_attribute]
          if val:
            logger.info('Entity id for %s %s is %s', entity_type, name, val)
            return val
    return name

  def _make_url(self, entity_type, *args):
    url = self.url
    url += "/%s" % entity_type
    for arg in args:
      url += "/%s" % str(arg)
    return url

  @retry
  def repartition_and_add_disk(self, disk_serial):
    return self.post("hades/repartition_and_add_disk",
                     value=disk_serial)


  def change_default_password(self, new_password):
    """
    Not tested
    """
    url = "utils/change_default_system_password"
    self.session = self._get_server_session('admin', 'admin')
    rsp = self.post(url, value=new_password,
                    headers={'content-type': 'application/json'})
    if rsp.ok:
      self.password = new_password
      self.session = self._get_server_session()
    return rsp

  def get_matching_entity(self, entity_type, match_attr, match_val):
    """
    Get all entities of type entity_type and return one entity whose
    attribute match_attr matches the match_val
    """
    logger.error('getting %s', entity_type)
    rsp = self.get(entity_type).json()
    if 'entities' in rsp:
      rsp = rsp['entities']
    for entity in rsp:
      if entity[match_attr] == match_val:
        return entity
    return None
