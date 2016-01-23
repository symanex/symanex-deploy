class AWSTools:
  '''AWSTools is a AWS helper class'''

  def __init__(self):
    self.__ec2_connection = None
    self.__autoscale_connection = None
    self.__elb_connection = None
    self.__r53_connection = None

  @property
  def ec2(self):
    if not self.__ec2_connection:
      import boto.ec2
      self.__ec2_connection = boto.ec2.connect_to_region('eu-west-1')
    return self.__ec2_connection

  @property
  def autoscale(self):
    if not self.__autoscale_connection:
      import boto.ec2.autoscale
      self.__autoscale_connection = boto.ec2.autoscale.connect_to_region('eu-west-1')
    return self.__autoscale_connection

  @property 
  def elb(self):
    if not self.__elb_connection:
      import boto.ec2.elb
      self.__elb_connection = boto.ec2.elb.connect_to_region('eu-west-1')
    return self.__elb_connection

  @property
  def route53(self):
    if not self.__r53_connection:
      import boto.route53
      self.__r53_connection = boto.route53.connect_to_region('eu-west-1')
    return self.__r53_connection

  def get_server(self, instance=False, instance_id=False):
    '''Server factory'''
    if not instance == False:
      return Server(instance=instance)
    elif not instance_id == False:
      return Server(instance=self.get_instances(filters={'instance_id':instance_id})[0])

  def get_servers(self, filters={}):
    '''Create a list of Server objects'''
    servers = []
    filter_defaults = {'instance-state-name':'running'}
    compiled_filters = dict(filter_defaults.items() + filters.items())
    for instance in self.get_instances(filters=compiled_filters):
      servers.append(Server(instance=instance))
    return servers

  def get_instances(self, filters={}):
    '''get a list of instances (by default all)'''
    return self.ec2.get_only_instances(filters=filters)

  def terminate_instances(self, filters={}):
    '''terminate instances (by default all)'''
    instances = []
    filter_defaults = {'instance-state-name':'running'}
    compiled_filters = dict(filter_defaults.items() + filters.items())
    for instance in self.get_instances(filters=compiled_filters):
      instance.terminate()
      instances.append(instance)
    return instances

  def print_instance_list(self, instances=[]):
    '''print a list of instances'''
    if not len(instances):
      instances = self.get_instances()
    for instance in instances:
      print "[" + instance.id + "] " + (instance.ip_address if instance.ip_address else "-") + " (" + instance.state + ")"

  def get_images(self, filters={}):
    '''get a list of images'''
    filter_defaults = {'name':'ubuntu/images/hvm/ubuntu-trusty-*'}
    compiled_filters = dict(filter_defaults.items() + filters.items())
    return self.ec2.get_all_images(filters=compiled_filters)

  def get_latest_image(self, filters={}):
    '''get the lastest image'''
    images = self.get_images(filters={})
    return sorted(images, key=lambda x: x.creationDate, reverse=True)[0]

#
# Server class
#
class Server:
  '''Server is a wrapper to simplify the work with AWS EC2 instances'''

  VALID_APP_SERVICE_ROLES = [ "nginx" ]

  default_key_name = 'symanex-test'
  default_roles = []
  default_apps = []
  default_connection_wait_time = 3.0
  default_connection_attempts = 30
  default_aws_zones = [ "eu-west-1a", "eu-west-1b", "eu-west-1c" ]
  default_aws_elb_listener = [ "80", "80", "HTTP" ]

  def __init__(self, instance=False, image=False, instance_type='t2.nano'):

    if not instance == False:
      self.__instance = instance
    elif not image == False:
      self.__instance = image.run(key_name=self.default_key_name,instance_type=instance_type).instances[0]
    else:
      self.__instance = AWSTools().get_latest_image().run(key_name=self.default_key_name,instance_type=instance_type).instances[0]
    
    self.__aws = AWSTools()

  def __update_instance(self):
    self.__instance = self.__aws.get_instances(filters={'instance-id':self.__instance.id})[0]

  def __update_tag(self, tag_name, items):
    self.__instance.add_tag(tag_name, value=','.join(set(items)))
    return self.__instance.tags[tag_name].split(',')

  @property
  def status(self):
    self.wait_for_instance()
    return self.__aws.ec2.get_all_instance_status(instance_ids=[self.__instance.id])[0]

  @property
  def instance_id(self):
    return self.__instance.id

  def get_instance(self):
    return self.__instance

  def wait_for_instance(self, quite=True):
    '''wait for the EC2 instance attached to this server to become available'''
    import time
    if not quite:
      import sys
      sys.stdout.write('waiting for instance ' + str(self.__instance.id) + ' ')
      sys.stdout.flush()
    while True:
      self.__update_instance()
      if not quite:
        sys.stdout.write('.')
        sys.stdout.flush()
      if self.__instance.state == "running":
        if not quite:
          print " available"
        break
      elif self.__instance.state == "pending":
        time.sleep(self.default_connection_wait_time)
        continue
      else:
        import errno
        raise EnvironmentError((errno.EHOSTDOWN, "instance %s is in an incompatible state: %s" % (self.__instance.id, self.__instance.state)))

  def wait_for_port(self, port, quite=True):
    '''wait for a specific port of the server to become available'''
    if not self.__instance.public_dns_name:
      import errno
      raise EnvironmentError((errno.EHOSTUNREACH, "instance %s does not have a public dns name to connect to" % (self.__instance.id)))
    import socket
    import time
    attempt = 0
    if not quite:
      import sys
      sys.stdout.write('waiting for port ' + str(port) + ' on ' + str(self.__instance.id) + ' ')
      sys.stdout.flush()
    while True:
      attempt += 1
      if not quite:
        sys.stdout.write('.')
        sys.stdout.flush()
      try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.default_connection_wait_time)
        s.connect((self.__instance.public_dns_name, port))
        if not quite:
          print " available"
      except (socket.timeout, socket.error) as e:
        if type(e).__name__ == "error":
          if e.errno != socket.errno.ECONNREFUSED:
            raise e
          else:
            time.sleep(self.default_connection_wait_time)
        if attempt < self.default_connection_attempts:
          continue
        else:
          if not quite:
            print " failed"
          raise socket.error((socket.errno.ECONNREFUSED, "unable to connect to port %i at %s" % (port, self.__instance.public_dns_name)))
      finally:
        s.close()
      break

  def get_roles(self):
    '''get a list of the Server's assigned roles'''
    roles = []
    try:
      roles = self.__instance.tags['Roles'].split(',')
    except:
      pass
    return roles

  def add_role(self, role_name):
    '''add a role to the Server'''
    roles = self.get_roles()
    roles.append(role_name)
    roles = set(roles)
    self.__update_tag("Roles", roles)
    return self

  def remove_role(self, role_name):
    '''remove a role from the Server'''
    roles = self.get_roles()
    roles.remove(role_name)
    self.__update_tag("Roles", roles)
    return self

  def get_apps(self):
    apps = []
    try:
      apps = self.__instance.tags['Apps'].split(',')
    except:
      pass
    return apps

  def add_app(self, app_name):
    '''add an app to the Server'''
    if not any(x in self.VALID_APP_SERVICE_ROLES for x in self.get_roles()):
      import errno
      raise EnvironmentError(errno.EPERM, "server does not have a compatible role, valid: %s" % (','.join(set(self.VALID_APP_SERVICE_ROLES))))
    apps = self.get_apps()
    apps.append(app_name)
    apps = set(apps)
    self.__update_tag("Apps", apps)
    self.attach_to_elb(app_name)
    # TODO: register DNS name with Route53 if not already there
    return self

  def remove_app(self, app_name):
    '''remove an app from the Server'''
    apps = self.get_apps()
    apps.remove(app_name)
    self.__update_tag("Apps", self.__apps)
    self.detach_from_elb(app_name)
    return self

  def get_key_name(self):
    '''get the key_pair name used to start the Server's EC2 instance'''
    return self.__instance.key_name

  def ssh(self, user="ubuntu", port=22, shell="bash -i", silent_wait=True, log_level="ERROR"):
    '''try to connect to the Server's EC2 instance by SSH'''
    import subprocess
    self.wait_for_instance(quite=silent_wait)
    self.wait_for_port(port, quite=silent_wait)
    print "Connecting to %s on port %s" % (self.__instance.public_dns_name, port)
    return subprocess.check_call('ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=%s -p %d -t %s@%s "stty sane; %s"' % (log_level, port, user, self.__instance.public_dns_name, shell), shell=True)

  def execute(self, command, user="ubuntu", port=22, silent_wait=True, log_level="ERROR"):
    '''execute a command on the Server'''
    return self.ssh(user=user, port=port, shell=command, silent_wait=silent_wait, log_level=log_level)

  def attach_to_elb(self, elb_name):
    '''attach the Server's EC2 instance to an AWS ELB'''
    if not filter(lambda elb: elb.name == elb_name, self.__aws.elb.get_all_load_balancers()):
      self.__aws.elb.create_load_balancer(name=elb_name, zones=self.default_aws_zones, listeners=[self.default_aws_elb_listener])
    self.__aws.elb.register_instances(elb_name, [self.__instance.id])
    return self.__aws.elb.get_all_load_balancers(load_balancer_names=[elb_name])[0]

  def detach_from_elb(self, elb_name):
    '''detach the Server's EC2 instance from an AWS ELB'''
    self.__aws.elb.deregister_instances(elb_name, [self.__instance.id])
    return self.__aws.elb.get_all_load_balancers(load_balancer_names=[elb_name])[0]

  def terminate(self):
    '''terminate the Server's EC2 instance'''
    self.__instance.terminate()

  def ping(self):
    import ansible.runner
    results = ansible.runner.Runner(
      host_list='./ec2.py',
      remote_user="ubuntu",
      pattern=self.__instance.id,
      module_name='ping'
    ).run()
    return results['contacted'][self.__instance.ip_address]['ping']

  def uptime(self):
    import ansible.runner
    results = ansible.runner.Runner(
      host_list="./ec2.py",
      remote_user="ubuntu",
      pattern=self.__instance.id,
      module_name='command',
      module_args='/usr/bin/uptime',
    ).run()
    return results['contacted'][self.__instance.ip_address]['stdout']

  def service(self, name, action):
    import ansible.runner
    action_args_string = ""
    if action == "enabled":
      action_args_string = "enabled=yes"
    elif action == "disabled":
      action_args_string = "enabled=no"
    else:
      action_args_string = "state=%s" % action
    results = ansible.runner.Runner(
      host_list="./ec2.py",
      remote_user="ubuntu",
      pattern=self.__instance.id,
      sudo=True,
      module_name='service',
      module_args="name=%s %s" % (name, action_args_string),
    ).run()
    msg = ""
    if 'failed' in results['contacted'][self.__instance.ip_address]:
      msg = results['contacted'][self.__instance.ip_address]['msg']
    elif 'changed' in results['contacted'][self.__instance.ip_address]:
      if 'state' in results['contacted'][self.__instance.ip_address]:
        msg = "%s: %s" % (results['contacted'][self.__instance.ip_address]['name'], results['contacted'][self.__instance.ip_address]['state'])
      elif 'enabled' in results['contacted'][self.__instance.ip_address]:
        if results['contacted'][self.__instance.ip_address]['enabled'] == True:
          msg = "%s: enabled" % (results['contacted'][self.__instance.ip_address]['name'])
        elif results['contacted'][self.__instance.ip_address]['enabled'] == False:
          msg = "%s: disabled" % (results['contacted'][self.__instance.ip_address]['name'])
      if results['contacted'][self.__instance.ip_address]['changed'] == True:
        msg += " (changed)"
      else:
        msg += " (not changed)"
    if not msg:
       msg = results['contacted'][self.__instance.ip_address]
    return msg
