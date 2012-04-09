#!/usr/bin/env python

import os
import socket
import sys
import threading
import traceback
import threading
import select
import paramiko
import Crypto.Random
import logging
import logging.handlers
import cStringIO
import pwd
import time
from optparse import OptionParser

from HSAgent import Control as HSAgent

from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol


class IgnoreHostKeyPolicy (paramiko.MissingHostKeyPolicy):
	def missing_host_key(self, client, hostname, key):
		return True

class ChannelClosedException(Exception):
    pass

class AppHostHeartBeat(threading.Thread):

    def __init__(self, apphost_agent, credentials):
        threading.Thread.__init__(self)

        self.apphost_agent = apphost_agent
        self.credentials = credentials
        self.daemon = True

    def run(self):
        logger.debug('Starting heartbeat thread')
        while True:
            try:
                logger.debug('Sending heartbeat to apphost')
                self.apphost_agent.heartbeat(self.credentials.app_id)
            except Exception as e:
                logger.error('Error while sending heartbeat: ' + str(e))
                break
                
            time.sleep(30)

class TerminalThrobber(threading.Thread):
    def __init__(self, channel):
        threading.Thread.__init__(self)
        self.channel = channel
        self.throb = True
        self.daemon = True
        self.message = ""

    def run(self):
        # We only do throbbing for interactive sessions
        if self.channel.requested_action != 'interactive':
            return

        self.channel.send("\r\nConnecting to app...  ")
        throbber = ['|', '/', '-', '\\']
        count = 0
        while self.throb:
            self.channel.send("\b" + throbber[count % len(throbber)])
            time.sleep(0.5)
            count += 1
        self.channel.send("\b%s\r\n\r\n" % self.message)

    def stop(self, message):
        self.message = message
        self.throb = False
        self.join()
            
          
class SSHGateway (paramiko.ServerInterface):

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            logger.debug('Handled a channel request, allowed a session')
            return paramiko.OPEN_SUCCEEDED
        logger.debug('Handled a channel request, denied: ' + kind)
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        logger.debug('Checking password for user %s' % (username))
        try:
            gatewayagent = open_agent_control(config['gateway-agent'])
            app_credentials = gatewayagent.fetch_ssh_credentials(username, password)
            logger.info('Username %s authenticated' % (username))
            self.app_credentials = app_credentials
            return paramiko.AUTH_SUCCESSFUL

        except HSAgent.AuthenticationError as ae:
            logger.warn('Failed authentication for user %s: %s' % (username, ae.message))
            return paramiko.AUTH_FAILED

        except HSAgent.NoDeploymentFoundError as ndf:
            # Could also accept AUTH and bail out with a message to the channel
            # to give user better feedback

            logger.warn("Couldn't find deployment for user %s: %s" % (username, ndf.message))
            return paramiko.AUTH_FAILED

        except (TTransport.TTransportException, socket.timeout) as e:
            logger.error("Error while communicating with gateway agent: %s" % e)
            return paramiko.AUTH_FAILED

        except Exception as e:
            logger.error('Error during authentication of user %s: %s' % (username, e))
            return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        auths = 'password'
        logger.debug('Returned allowed auths: ' + auths)
        return auths

    def check_channel_exec_request(self, channel, command):
        channel.user_command = command
        channel.requested_action = 'execute'
        logger.debug('Handled an exec request: ' + command)
        self.event.set()
        return True

    def check_channel_shell_request(self, channel):
        logger.debug('Handled a shell request')
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        channel.term = term
        channel.width = width
        channel.height = height
        channel.requested_action = 'interactive'
        logger.debug('Handled a PTY request')
        return True

    def check_channel_subsystem_request(self, channel, name):
        if name == 'sftp':
            logger.debug('Handled a subsystem request, allowed sftp')
            # FIXME: Probably better done via subsystem handlers
            channel.requested_action = 'sftp'
            self.event.set()
            return True

        logger.debug('Handled a subsystem request, denied: ' + name)
        return False

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        if channel.paired_interactive_session and channel.paired_interactive_session.active:
            logger.debug('Handled a resize request, new resolution: %ix%i' % (width, height))
            channel.paired_interactive_session.resize_pty(width, height)
        

def open_agent_control(host):
    socket = TSocket.TSocket(host, 9090)

    # Set a timeout for the Thrift communication. This is honored for setting
    # up the TCP socket as well as the actualy RPC communication!
    socket.setTimeout(5 * 1000)

    transport = TTransport.TFramedTransport(socket)
    transport.open()

    protocol = TBinaryProtocol.TBinaryProtocol(transport)

    return HSAgent.Client(protocol)
   

def configure_logger():
    logtemp = logging.getLogger('hs-sshgw')

    if config['verbose']:
        level = logging.DEBUG
    else:
        level = logging.INFO
            
    logtemp.setLevel(level)
    lh = None
    lf = None

    logtarget = config['log-target']

    format = '%(name)s[%(process)s]: %(message)s'

    if logtarget == 'syslog':
        lh = logging.handlers.SysLogHandler(address='/dev/log', facility=logging.handlers.SysLogHandler.LOG_DAEMON)

        # Push messages of severity CRITICAL also to stdout since they prevent
        # the ssh-gateway from running
        stdout = logging.StreamHandler()
        stdout.setLevel(logging.CRITICAL)
        stdout.setFormatter(logging.Formatter(format))
        logtemp.addHandler(stdout)

    elif logtarget == 'stdout':
        lh = logging.StreamHandler()
        format = '%(asctime)s '+ format
    else:
        print "\n*** Unsupported log target ***\n"
        parse_options(print_help=True)
        sys.exit(1)

    lf = logging.Formatter(format)
    lh.setFormatter(lf)
    logtemp.addHandler(lh)

    # Hackaround-disable paramiko's builtin logger since we handle all exceptions ourselves nicely
    logging.getLogger('paramiko.transport').addHandler(logging.FileHandler('/dev/null'))
    return logtemp


def copy_data(source, drain, copy_stderr):
    while source.recv_ready():
        data = source.recv(4096)
        #print ('stdin', 'stdout')[copy_stderr] + ': ' + repr(data)
        if len(data) == 0: raise ChannelClosedException()
        drain.sendall(data)

    # We only want to copy stderr when we're collecting data
    # from the app channel
    while copy_stderr and source.recv_stderr_ready():
        data = source.recv_stderr(4096)
        if len(data) == 0: raise ChannelClosedException()
        drain.sendall_stderr(data)


def copy_bidirectional_blocking(client, server):

    socklist = (client.fileno(), server.fileno())
        
    # Copy data between the two SSH channels
    channel_closed = False
    abort = False
    while not abort:
        select.select(socklist, socklist, socklist, 1)

        # Force a final run after an abort condition triggered
        # to make sure that all channels are flushed
        if channel_closed == True:
            abort = True

        # Copy data from user to app
        try:
            copy_data(client, server, False)
        except ChannelClosedException:
            channel_closed = True

        # If we receive an EOF we need to shutdown the sending side of the peer's socket
        # to generate an appropriate EOF.
        # This is necessary for tools like scp to terminate correctly
        if client.closed or client.eof_received:
            server.shutdown(1)
            channel_closed = True

        # Copy data from app to user
        try:
            copy_data(server, client, True)
        except ChannelClosedException:
            channel_closed = True

        if server.closed or server.eof_received:
            client.shutdown(1)
            channel_closed = True


def read_host_keys():
    rsakey = config['host-rsa-key']
    if rsakey:
        try:
            config['loaded-host-rsa-key'] = paramiko.RSAKey(filename=rsakey)
        except Exception as e:
            logger.critical('Failed to load RSA host key: ' + str(e))

    dsakey = config['host-dsa-key']
    if dsakey:
        try:
            config['loaded-host-dsa-key'] = paramiko.DSSKey(filename=dsakey)
        except Exception as e:
            logger.critical('Failed to load DSA host key: ' + str(e))

    if not ('loaded-host-rsa-key' in config or 'loaded-host-dsa-key' in config):
        logger.critical('Failed to load any host key')
        sys.exit(1)


def add_host_keys(transport):
    if 'loaded-host-rsa-key' in config:
        transport.add_server_key(config['loaded-host-rsa-key'])

    if 'loaded-host-dsa-key' in config:
        transport.add_server_key(config['loaded-host-dsa-key'])

    # Optional, requires /etc/ssh/moduli
    transport.load_server_moduli()


def send_message(channel, message):
    if channel.requested_action == 'interactive':
        channel.send(message + "\r\n\r\n")


def cleanup(userchan, app):
    usertransport = userchan.get_transport()
    logger.info('User %s disconnected' % (usertransport.get_username())) 

    # We explicitly need to close the user's channel before the transport
    # to provide a nice shutdown for the client, otherwise ssh(1) get's confused

    userchan.close()
    time.sleep(0.5)
    usertransport.close()
    if app: app.close()

def load_ssh_app(credentials):
    logger.debug("Connecting to agent %s, loading app %s" % (credentials.agent_ip, credentials.app_id))

    try:
        apphost_agent = open_agent_control(credentials.agent_ip)
        ip_address = apphost_agent.start_vm_protocol(credentials.app_id, 'ssh')
    except (TTransport.TTransportException, socket.timeout) as e:
        logger.error("Error while communicating with apphost agent %s: %s" % (credentials.agent_ip, e))
        raise e

    return (ip_address, apphost_agent)


def run_session(client):
    user = paramiko.Transport(client)
    add_host_keys(user)
    sshgw = SSHGateway()

    # We initialized a transport and now start SSH negotiation
    try:
        user.start_server(server=sshgw)
    except (paramiko.SSHException, EOFError) as e:
        logger.warn('SSH negotiation failed: ' + str(e))
        sys.exit(1)

    # Waiting for client to authenticate and initiate a session
    # FIXME: We only support a single channel per Transport
    userchan = user.accept(60)
    if userchan is None:
        logger.warn('Client failed to open a channel')
        sys.exit(1)

    # Waiting for client to request something
    # This event is triggered from one of the handlers
    sshgw.event.wait(60)
    if not sshgw.event.isSet():
        logger.warn('Client never asked for a shell or sftp.')
        sys.exit(1)


    # Parse the private key provided by the CC
    app_private_key = None
    try:
        keyhandle = cStringIO.StringIO(sshgw.app_credentials.sshkey)
        app_private_key = paramiko.RSAKey(file_obj=keyhandle)
    except Exception as e:
        logger.error('Failed to parse SSH private key for client connection: ' + str(e))
        send_message(userchan, 'Failed to get credentials for app')
        cleanup(userchan, None)
        return 1

    spinner = TerminalThrobber(userchan)
    spinner.start()

    try:
        (ssh_host, apphost_agent) = load_ssh_app(sshgw.app_credentials)
    except Exception as e:
        spinner.stop("error!")
        logger.error('Failed to load App %s via agent %s for SSH usage: %s' % (sshgw.app_credentials.app_id, sshgw.app_credentials.agent_ip, e))
        send_message(userchan, 'Failed to load app')
        cleanup(userchan, None)
        return 1

    logger.debug('Connecting to host %s using key %s %s' % (ssh_host, app_private_key.get_name(), app_private_key.get_base64()))

    # Connect to the app
    app = paramiko.SSHClient()
    app.set_missing_host_key_policy(IgnoreHostKeyPolicy())

    try:
        app.connect(hostname=ssh_host, username='app', pkey=app_private_key, timeout=10, allow_agent=False, look_for_keys=False)
    except Exception as e:
        spinner.stop("error!")
        logger.error('Failed to connect to app %s: %s' %  (ssh_host, str(e)))
        send_message(userchan, 'Failed to connect to app')
        cleanup(userchan, app)
        return 1
	
    spinner.stop("connected!")
    appchan = None

    if userchan.requested_action == 'sftp':
        appchan = app.get_transport().open_session()
        appchan.invoke_subsystem('sftp')

    elif userchan.requested_action == 'interactive':
        appchan = app.invoke_shell(userchan.term, userchan.width, userchan.height)
        userchan.paired_interactive_session = appchan
#        appchan.send("cd code\n")

    elif userchan.requested_action == 'execute':
        appchan = app.get_transport().open_session()
        appchan.exec_command(userchan.user_command)
    
    else:
        logger.warn('Unknown or unset action for userchannel: %s, aborting' % userchan.requested_action)
        cleanup(userchan, app)
        return 1

    heartbeat = AppHostHeartBeat(apphost_agent, sshgw.app_credentials)
    heartbeat.start()

    copy_bidirectional_blocking(userchan, appchan)

    send_message(userchan, 'Terminating session.')

    # This could block indefinitely if the app never sends a return code
    # and doesn't tear down the connection... ignore for now
    rc = appchan.recv_exit_status()

    logger.debug('Shutting down session with exit code %d' % rc)
    userchan.send_exit_status(rc)
        
    cleanup(userchan, app)
    return 0

def drop_privileges():

    # Nothing to do, not running as root
    if os.getuid() != 0:
        return

    username = config['daemon-user']
    uid = pwd.getpwnam(username)[2]

    if not uid:
        raise "User %s doesn't exist" % (username)

    os.setuid(uid)

    if os.getuid() != uid or os.geteuid() != uid:
        raise "Failed to change user to " + username
        sys.exit(1)


def parse_options(print_help=False):
    parser = OptionParser()

    parser.add_option('-l', '--listen-address', action='store', dest='bind-address', default='0.0.0.0',
        help="Bind to this interface [default: %default]")
    parser.add_option('-p', '--port', action='store', type=int, dest='listen-port', default=2200,
        help="Listen on this port [default: %default]")
    parser.add_option('--host-rsa-key', action='store', dest='host-rsa-key', default='/etc/hs/sshgateway/ssh_host_rsa_key',
        help="Use this file as RSA host key [default: %default]")
    parser.add_option('--host-dsa-key', action='store', dest='host-dsa-key', default='/etc/hs/sshgateway/ssh_host_dsa_key',
        help="Use this file as DSA host key [default: %default]")
    parser.add_option('--log-target', action='store', dest='log-target', default='syslog',
        help="Send log output to this target. Can be either 'syslog', 'stdout' or a path to a file. [default: %default]")
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', default=False,
        help="Log more information during the sesion. Only one -v is supported")
    parser.add_option('-g', '--gateway-agent', action='store', dest='gateway-agent', default='127.0.0.1',
        help="Address or hostname for the Gateway agent. [default: %default]")
    parser.add_option('-u', '--user', action='store', dest='daemon-user', default='nobody',
        help="When run as root, use this username after reading the host keys and binding to the listen-socket. [default: %default]")

    if print_help:
        parser.print_help()
        return

    (options, args) = parser.parse_args()

    return options.__dict__


def main():
    global config, logger

    config = parse_options()
    logger = configure_logger()

    read_host_keys()

    # Bind to the socket
    try:
        logger.info('Listening for connections on %s:%i' % (config['bind-address'], config['listen-port']))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((config['bind-address'], config['listen-port']))

        # Set a timeout so that the accept loop doesn't block too long in low-traffic environments
        sock.settimeout(5)
    except Exception as e:
        logger.critical('Bind failed: ' + str(e))
        sys.exit(1)

    # If we're run as root, drop the privileges after binding to the port.
    try:
        drop_privileges()
    except Exception as e:
        logger.critical('Failed to change user to %s: %s' %  (username, str(e)))
        sys.exit(1)

    # Listen for connections
    try:
        sock.listen(100)
    except Exception as e:
        logger.critical('Listen failed: ' + str(e))
        sys.exit(1)

    # Accept loop
    try:
        while True:
            client = None

            # Wait for a connection or timeout
            try:
                client, addr = sock.accept()
            except socket.timeout:
                pass

            # Try to reap any leftover childs
            try:
                while os.wait3(os.WNOHANG)[1] != 0:
                    continue
            except OSError:
                pass

            # There was no client connected, try again
            if not client:
                continue

            # We've got a connection, fork!
            logger.info('Client connected from ' + ':'.join(map(str, addr)))
            pid = os.fork()

            if pid == 0:
                # We are a child, run a session and then exit
                Crypto.Random.atfork()
                sock.close()
                run_session(client)
                # When run_sesion returns everything is cleaned up, we can disconnect
                sys.exit(0)
            else:
                # We are the parent, we need to release the client socket
                client.close()


    except Exception as e:
        logger.critical('*** Caught exception: ' + str(e.__class__) + ': ' + str(e))
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__': main()
