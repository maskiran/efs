import gflags
import logging
import os
import traceback


gflags.DEFINE_string('logdir', None, 'Directory in which log is created')


class NullHandler(logging.Handler):
    def emit(self, record):
        pass


def setup_logging(logdir, logger_name='efs', stdout=False):
  """
  Initialize the logger for logger_name. A file 'output.txt' is created
  in the logdir. The level is set to 'INFO' and above. Another file
  'debug.txt' is created in the same directory with level set to
  'DEBUG'. This file also shows the trace of the function calls instead
  of the just the last file name.
  If stdout is True, then a stream handler is added to show the info on
  stdout. The level is set to INFO for the stream handler.
  """
  logger = logging.getLogger(logger_name)
  # logger always starts with level 1, so it processes all the
  # messages.
  logger.setLevel(1)
  # remove all the existing handlers, if any
  handlers = logger.handlers[:]
  for handler in handlers:
    logger.removeHandler(handler)
  if logdir:
    if not os.path.exists(logdir):
      os.makedirs(logdir)
    fname = os.path.join(logdir, 'output.txt')
    handler = logging.FileHandler(fname, 'w')
    log_format = "%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s"
    formatter = logging.Formatter(log_format, "%Y-%m-%d %H:%M:%S")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    handler.setLevel(logging.INFO)
    #_add_debug_handler(logger, logdir)
  if stdout:
    handler = logging.StreamHandler()
    log_format = "%(asctime)s %(message)s"
    formatter = logging.Formatter(log_format)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    handler.setLevel(logging.INFO)
  return logger


def _add_debug_handler(logger, logdir):
  fname = os.path.join(logdir, 'debug.txt')
  handler = logging.FileHandler(fname, 'w')
  log_format = "%(asctime)s %(levelname)s [%(flow)s] %(message)s"
  formatter = logging.Formatter(log_format)
  handler.setFormatter(formatter)
  logger.addHandler(handler)
  # add a filter to get the field 'flow' for the format
  class FlowFilter(logging.Filter):
    def filter(self, record):
      flow = _get_call_flow()
      record.flow = " > ".join(flow)
      return True
  handler.addFilter(FlowFilter())
  handler.setLevel(logging.DEBUG)


def _get_call_flow():
  flow = []
  stack = traceback.extract_stack()
  for item in stack:
    # item is (filename, linenum, module, func)
    file_name = item[0]
    line_no = item[1]
    # if fname is __init__.py, its going to the logging module,
    # not interested at that level
    if 'logging/__init__.py' in file_name:
      break
    flow.append(os.path.basename(file_name) + ':' + str(line_no))
  return flow
