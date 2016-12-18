#
"""
     module: ciscorouter_rtbh_connector.py
     short_description: This Phantom app connects to Cisco IOS-XE
     platform devices and provided you have a properly configured
     trigger router configured to push routes, will effectively firewall
     interal to an organization - security in depth
     author: Todd Ruch, World Wide Technology
     Revision history:
     See github repo for changelog:
     https://github.com/taruch/phantom_ciscorouter_rtbh

     Copyright (c) 2016 World Wide Technology, Inc.

     This program is free software: you can redistribute it and/or
     modify it under the terms of the GNU Affero General Public License
     as published by the Free Software Foundation, either version 3
     of the License, or (at your option) any later version.

     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU Affero General Public License for more details.


"""
#
# Phantom App imports
#
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
#
#  system imports
#
import simplejson as json
import time
import paramiko
from netaddr import IPNetwork

# ========================================================
# AppConnector
# ========================================================


class CSR_Connector(BaseConnector):

    BANNER = "CiscoRouter"

    def __init__(self):
        """
        Instance variables
        """
        # Call the BaseConnectors init first
        super(CSR_Connector, self).__init__()

        self.username = ''
        self.password = ''
        self.device = ''
        self.next_hop_IP = ''
        self.destination_network = ''
        self.network = ''
        self.subnetmask = ''
        self.tag = ''
        self.name = ''

    def validate_parameters(self, param):
        return phantom.APP_SUCCESS

    def initialize(self):
        """
        This is an optional function that can be implemented by the
        AppConnector derived class. Since the configuration dictionary
        is already validated by the time this function is called,
        it's a good place to do any extra initialization of any internal
        modules. This function MUST return a value of either
        phantom.APP_SUCCESS or phantom.APP_ERROR.  If this function
        returns phantom.APP_ERROR, then AppConnector::handle_action
        will not get called.
        """
        self.debug_print("{0} INITIALIZE {1}".format(CSR_Connector.BANNER,
                                                     time.asctime()))
        self.debug_print("INITAL CONFIG: {0}".format(self.get_config()))
        return phantom.APP_SUCCESS

    def finalize(self):
        """
        This function gets called once all the param dictionary
        elements are looped over and no more handle_action calls are
        left to be made. It gives the AppConnector a chance to loop
        through all the results that were accumulated by multiple
        handle_action function calls and create any summary if
        required. Another usage is cleanup, disconnect from remote
        devices etc.
        """
        self.debug_print("{0} FINALIZE Status: {1}".format(
                                                          CSR_Connector.BANNER,
                                                          self.get_status()))
        return

    def handle_exception(self, exception_object):
        """
        All the code within BaseConnector::_handle_action is within
        a 'try: except:' clause.  Thus if an exception occurs during
        the execution of this code it is caught at a single place. The
        resulting exception object is passed to the
        AppConnector::handle_exception() to do any cleanup of it's own
        if required. This exception is then added to the connector run
        result and passed back to spawn, which gets displayed in the
        Phantom UI.
        """
        self.debug_print("%s HANDLE_EXCEPTION %s" % (CSR_Connector.BANNER,
                                                     exception_object))
        return

    def _test_connectivity(self, param):
        """
        Called when the user depresses the test connectivity
        button on the Phantom UI.
        """
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        self.debug_print("%s TEST_CONNECTIVITY %s" % (CSR_Connector.BANNER,
                                                      param))
        config = self.get_config()

        try:
            self.username = config["username"]
            self.password = config["password"]
            self.device = config["trigger_host"]
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))
            return self.set_status_save_progress(phantom.APP_ERROR,
                                                 "KeyError attempting to "
                                                 "parse organization ID "
                                                 "and name")

        self.debug_print("Username: {0}, Password: {1}".format(self.username,
                                                               self.password))

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.device, username=self.username,
                    password=self.password, allow_agent=False,
                    look_for_keys=False)
        csr_conn = ssh.invoke_shell()
        self.debug_print(type(csr_conn))
        csr_conn.send('show version\n')
        time.sleep(1)
        resp = csr_conn.recv(99999)
        csr_conn.close()
        ssh.close()
        self.debug_print("Initial test connectivity to device resp: "
                         "{0}".format(resp))

        if resp:
            self.debug_print("Connected to device: {0}".format(resp))
            return self.set_status_save_progress(phantom.APP_SUCCESS,
                                                 "SUCCESS Connected to device")
        else:
            self.debug_print("Unable to connect to device: {0}".format(resp))
            return self.set_status_save_progress(phantom.APP_ERROR, "FAILURE! "
                                                 "Unable to connect to device")

    def listStaticBlackHoledIPs(self, param):
        """
        """
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        config = self.get_config()
        self.debug_print(config)

        try:
            self.username = config["username"]
            self.password = config["password"]
            self.device = config["trigger_host"]
            self.next_hop_IP = config['route_to_null']
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))

        self.debug_print("Device: {0}, User: {1}, Password: {2}".format(
                         self.device, self.username, self.password))
        # Get the current list of static routes from the Target Host
        route_list = self._get_StaticBlackHoledIPs(self.username,
                                                   self.password,
                                                   self.device,
                                                   self.next_hop_IP)

        self.debug_print("listStaticBlackHoledIP's result RAW: {0}".format(
                                                                   route_list))

        # Even if the query was successfull the data might not be available
        if len(route_list) == 0:
            return action_result.set_status(phantom.APP_ERROR,
                                            'Query returned with no data')
        else:
            for dest in route_list:
                action_result.add_data({'blackholed-network': dest})
            summary = "Query returned {0} routes".format(len(route_list))
            action_result.update_summary({'message': summary})
            self.set_status_save_progress(phantom.APP_SUCCESS, summary)
            # action_result.set_status(phantom.APP_SUCCESS)

        return action_result.get_status()

    def setBlockNetwork(self, param):
        """
        Will block a network based on Network/Mask
        """
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        self.debug_print("Input Param: {0}".format(param))

        # Set variables based on what is provided in the "asset" and is
        # provided by the user
        config = self.get_config()
        self.debug_print("Go get all the things!")
        try:
            self.username = config["username"]
            self.password = config["password"]
            self.device = config["trigger_host"]
            self.next_hop_IP = config["route_to_null"]
            self.destination_network = param["destination_network"]

        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))
            self.debug_print("Device: {0}, User: {1}, Password: {2}".format(
                                        self.device, self.user, self.password))
            self.debug_print("next_hop_ip: {0}".format(self.next_hop_IP))
            self.debug_print("tag: {0}".format(self.tag))
            self.debug_print("destination_network: {0}".format(
                                                     self.destination_network))

        # TAG is optional - may not exist
        try:
            self.tag = config['tag']
        except KeyError:
            self.debug_print("INFO: No tag in config: {0}".format(KeyError))
            pass
        # NAME is optional - may not exist
        try:
            self.name = param['name']
        except KeyError:
            self.debug_print("INFO: No name in param: {0}".format(KeyError))
            pass

        if self.validate_ip():
            self.debug_print("Validate_IP function returns: True")
        else:
            return action_result.set_status(phantom.APP_ERROR, "IP not valid: "
                                            "{0}".format(param[
                                                       "destination_network"]))
        # STUB - Started to seperate ip/mask so I could use the contains
        # element in JSON
        ip = IPNetwork(self.destination_network)
        network = str(ip.ip)
        subnetmask = str(ip.netmask)
        self.debug_print("Dest_Net: {0}, Network: {1}, SubnetMask: "
                         "{2}, tag: {3}".format(self.destination_network,
                                                network, subnetmask, self.tag))
        # END STUB

        # csr_conn = self.get_Cisco_Session()
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.device, username=self.username,
                    password=self.password, allow_agent=False,
                    look_for_keys=False)
        csr_conn = ssh.invoke_shell()
        self.debug_print(type(csr_conn))

        csr_conn.send('conf t\n')
        time.sleep(1)
        resp = csr_conn.recv(99999)
        self.debug_print("conf t _ resp: {0}".format(resp))
        tag = ''
        name = ''
        if self.tag:
            tag = "tag " + str(self.tag)
        if self.name:
            name = "name " + self.name
        add_Route = 'ip route {0} {1} {2} {3} {4}\n'.format(network,
                                                            subnetmask,
                                                            self.next_hop_IP,
                                                            tag, name)
        self.debug_print('Add Route Statement: {0}'.format(add_Route))
        csr_conn.send(add_Route)
        time.sleep(1)
        resp = csr_conn.recv(99999)
        csr_conn.close()
        ssh.close()
        self.debug_print("show ip static route resp: {0}".format(resp))

        route_list = self._get_StaticBlackHoledIPs(self.username,
                                                   self.password,
                                                   self.device,
                                                   self.next_hop_IP)
        for i in xrange(len(route_list)):
            if self.destination_network in route_list[i]:

                summary = "Successfully added {0}".format(
                                                     self.destination_network)
                action_result.update_summary({'message': summary})
                return action_result.set_status(phantom.APP_SUCCESS,
                                                "Successfully added "
                                                "{0}".format(
                                                     self.destination_network))
        else:
            return action_result.set_status(phantom.APP_ERROR)

    def delBlockNetwork(self, param):
        """
        Will remove a blocked network based on IP/NM
        """
        # Add an action result to the App Run
        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        config = self.get_config()
        self.debug_print(param)

        try:
            self.username = config["username"]
            self.password = config["password"]
            self.device = config["trigger_host"]
            self.next_hop_IP = config['route_to_null']
            self.destination_network = param["destination_network"]
        except KeyError:
            self.debug_print("Error: {0}".format(KeyError))
            self.debug_print("Device: {0}, User: {1}, Password: {2}".format(
                                    self.device, self.username, self.password))
            self.debug_print("next_hop_ip: {0}".format(self.next_hop_IP))
            self.debug_print("tag: {0}".format(self.tag))
            self.debug_print("destination_network: {0}".format(
                                                     self.destination_network))

        validate_return = self.validate_ip()
        self.debug_print("Validate_IP function returns: "
                         "{0}".format(validate_return))
        if not validate_return:
            return action_result.set_status(phantom.APP_ERROR, "IP not valid: "
                                            "{0}".format(param[
                                                       "destination_network"]))

        ip = IPNetwork(self.destination_network)
        network = str(ip.ip)
        subnetmask = str(ip.netmask)

        # csr_conn = self.get_Cisco_Session()
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.device, username=self.username,
                    password=self.password, allow_agent=False,
                    look_for_keys=False)
        csr_conn = ssh.invoke_shell()
        self.debug_print(type(csr_conn))

        csr_conn.send('conf t\n')
        time.sleep(1)
        resp = csr_conn.recv(99999)
        self.debug_print("conf t _ resp: {0}".format(resp))
        del_Route = 'no ip route {0} {1} {2}\n'.format(network, subnetmask,
                                                       self.next_hop_IP)
        csr_conn.send(del_Route)
        time.sleep(1)
        resp = csr_conn.recv(99999)
        csr_conn.close()
        ssh.close()
        self.debug_print("show ip static route resp: {0}".format(resp))

        route_list = self._get_StaticBlackHoledIPs(self.username,
                                                   self.password,
                                                   self.device,
                                                   self.next_hop_IP)
        for i in xrange(len(route_list)):
            if self.destination_network in route_list[i]:
                return action_result.set_status(phantom.APP_ERROR,
                                                "Route {0} not deleted".format(
                                                     self.destination_network))
        else:
            return action_result.set_status(phantom.APP_SUCCESS,
                                            "Successfully removed "
                                            "{0}".format(
                                                     self.destination_network))

    def _get_StaticBlackHoledIPs(self, username, password, device,
                                 next_hop_IP):
        """
        """
        route_list = []
        # csr_conn = self.get_Cisco_Session()

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(self.device, username=self.username,
                    password=self.password, allow_agent=False,
                    look_for_keys=False)
        csr_conn = ssh.invoke_shell()

        self.debug_print(type(csr_conn))
        # Set the terminal length to infinite so that all routes
        # are listed in the response
        csr_conn.send('terminal length 0\n')
        time.sleep(1)
        resp = csr_conn.recv(99999)
        self.debug_print("set terminal length resp: {0}".format(resp))
        # Send the show ip static route command to the router
        csr_conn.send('show ip static route\n')
        time.sleep(5)
        resp = csr_conn.recv(999999)
        csr_conn.close()
        ssh.close()
        self.debug_print("show ip static route resp: {0}".format(resp))
        findstring = "via " + self.next_hop_IP + " [A]"
        for i in resp.split('\n'):
            if findstring in i:
                i = i.replace('\r', '')
                route_list.append(i)
        return route_list

    def validate_ip(self):
        # Determine if mask is included in IP
        ip_and_mask = self.destination_network.split('/')
        if len(ip_and_mask) != 2:
            self.debug_print("Network Mask not included in"
                             " {0}".format(self.destination_network))
            # Normalize the IP
            self.destination_network = str(self.destination_network) + '/32'
        ip = ip_and_mask[0].split('.')
        if len(ip) != 4:
            return False
        for x in ip:
            if not x.isdigit():
                return False
            i = int(x)
            if i < 0 or i > 255:
                return False
        return True

    def handle_action(self, param):
        """
        This function implements the main functionality of the AppConnector.
        It gets called for every param dictionary element in the parameters
        array. In it's simplest form it gets the current action identifieri
        and then calls a member function of it's own to handle the action.
        This function is expected to create the results of the action run
        that get added to the connector run. The return value of this function
        is mostly ignored by the BaseConnector. Instead it will just loop
        over the next param element in the parameters array and call
        handle_action again.

        We create a case structure in Python to allow for any number of
        actions to be easily added.
        """

        # action_id determines what function to execute
        action_id = self.get_action_identifier()
        self.debug_print("{0} HANDLE_ACTION action_id:{1} parameters:\n"
                         "{2}".format(CSR_Connector.BANNER, action_id, param))

        supported_actions = {"test connectivity": self._test_connectivity,
                             "list_networks": self.listStaticBlackHoledIPs,
                             "block_ip": self.setBlockNetwork,
                             "unblock_ip": self.delBlockNetwork,
                             "block_network": self.setBlockNetwork,
                             "unblock_network": self.delBlockNetwork
                             }

        run_action = supported_actions[action_id]

        return run_action(param)


"""
Logic for testing interactively e.g.
python2.7 ./cisco_csr_connector.py ./test_jsons/test.json
If you don't reference your module with a "./" you will encounter a
'failed to load app json'
"""

if __name__ == '__main__':

    import sys
    # import pdb

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print ("%s %s" % (sys.argv[1], json.dumps(in_json, indent=4)))
        # pdb.set_trace()

        connector = CSR_Connector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print ("%s %s" % (connector.BANNER, json.dumps(json.loads(ret_val),
                          indent=4)))

    exit(0)
