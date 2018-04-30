########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.


# ctx is imported and used in operations
from cloudify import ctx
import boto3
from collections import OrderedDict
import xmltodict
from cloudify.exceptions import NonRecoverableError

# put the operation decorator on any function that is a task
from cloudify.decorators import operation

regionName = ''
#input REGION NAME
customerGatewayId = ''
#input CustomerGatewayId
awsAccessKeyId= ''
awsSecretAccessKey= ''

@operation
def start(**kwargs):
    properties = ctx.node.properties
    ConnectionInfo = properties.get('connection_infomation', {})
    ConnectionInfo.update(kwargs.get('connection_infomation', {}))
    global customerGatewayId
    customerGatewayId = ConnectionInfo.get('customer_gateway_id')
    print('customer_gateway_id')
    print(customerGatewayId)


    if(customerGatewayId == ''):
        ctx.logger.info('Not set customer gateway id')
        raise NonRecoverableError("Not set customer gateway id")

    global awsAccessKeyId
    awsAccessKeyId = ConnectionInfo.get('aws_access_key_id')
    print('awsAccessKeyId')
    print awsAccessKeyId
    global awsSecretAccessKey
    awsSecretAccessKey = ConnectionInfo.get('aws_secret_access_key')
    print('awsSecretAccessKey')
    print awsSecretAccessKey
    global regionName
    regionName = ConnectionInfo.get('ec2_region_name')
    print('region_name')
    print(regionName)

    try:
        get_connection_config()
    except WaitInterval:
        print "Catch wait interwal"
        return ctx.operation.retry(message='Still waiting for connection id' + ctx.node.properties['customer_gateway_id'])


class WaitInterval(Exception):
   """Goi to wait interval"""
   pass


def get_vpn_config(ec2, regions):
    global_config = OrderedDict()
    mark = iter(range(100, 4000, 100))
    for region in regions:
        print("Looking in %s" % region)

        response = ec2.describe_vpn_connections(
        )
        print(response)
        local_config = parse_vpn_response(response, mark)
        global_config.update(local_config)

    return global_config

def parse_vpn_response(response, mark):
    config = OrderedDict()
    find = False
    for connection in response['VpnConnections']:


        if connection['CustomerGatewayId'] != customerGatewayId:
            continue
        print "connection[State]"
        print  connection['State']
        if connection['State'] == 'pending':
            ctx.operation.retry(message='Still waiting for the VM to start..',
                                       retry_after=20)
            raise WaitInterval

        if connection['State'] != 'available':
            continue




        find = True

        vpn_id = connection['VpnConnectionId']

        config = OrderedDict()
        items = connection.items()
        print("items")
        for item in items:
            print (item)


        vpn_config = xmltodict.parse(connection['CustomerGatewayConfiguration'])

        for index, tunnel in enumerate(vpn_config['vpn_connection']['ipsec_tunnel']):
            tunnel_key = 'tunnel-%s' % index
            config[tunnel_key] = OrderedDict()

            config[tunnel_key]['right_inside_ip'] = '%s/%s' % (
                tunnel['customer_gateway']['tunnel_inside_address']['ip_address'],
                tunnel['customer_gateway']['tunnel_inside_address']['network_cidr'])
            config[tunnel_key]['right_outside_ip'] = tunnel['customer_gateway']['tunnel_outside_address'][
                'ip_address']
            config[tunnel_key]['right_asn'] = tunnel['customer_gateway']['bgp']['asn']
            config[tunnel_key]['left_inside_ip'] = '%s/%s' % (
                tunnel['vpn_gateway']['tunnel_inside_address']['ip_address'],
                tunnel['vpn_gateway']['tunnel_inside_address']['network_cidr'])
            config[tunnel_key]['left_outside_ip'] = tunnel['vpn_gateway']['tunnel_outside_address'][
                'ip_address']
            config[tunnel_key]['left_asn'] = tunnel['vpn_gateway']['bgp']['asn']
            config[tunnel_key]['psk'] = tunnel['ike']['pre_shared_key']
            config[tunnel_key]['mark'] = next(mark)

    if (find == False):
        ctx.logger.info('No available connection for ' + customerGatewayId)
        raise WaitInterval

    return config


def get_connection_config():

    print awsAccessKeyId
    print awsSecretAccessKey
    print (regionName)
    ec2 = boto3.client('ec2',
                       aws_access_key_id=awsAccessKeyId,
                       aws_secret_access_key=awsSecretAccessKey,
                       region_name=regionName
                       )
    regions_list = []
    regions_list.append(regionName)
    config = get_vpn_config(ec2, regions_list)
    print config
    print("Out config")

    print "peer_1_ip: " + config['tunnel-0']['left_outside_ip']
    ctx.instance.runtime_properties['peer_1_ip'] = config['tunnel-0']['left_outside_ip']
    print "peer_1_shared_secret: " + config['tunnel-0']['psk']
    ctx.instance.runtime_properties['peer_1_shared_secret'] = config['tunnel-0']['psk']
    print "peer_1_tunnel_ip: " + config['tunnel-0']['right_inside_ip']
    ctx.instance.runtime_properties['peer_1_tunnel_ip'] = config['tunnel-0']['right_inside_ip']
    peer_1_tunnel_peer = config['tunnel-0']['left_inside_ip']
    ctx.instance.runtime_properties['peer_1_tunnel_peer'] = config['tunnel-0']['left_inside_ip']
    peer_1_tunnel_peer = peer_1_tunnel_peer[0:peer_1_tunnel_peer.find("/")]
    print "peer_1_tunnel_peer: " + peer_1_tunnel_peer
    ctx.instance.runtime_properties['peer_1_tunnel_peer'] = peer_1_tunnel_peer
    print "peer_2_ip: " + config['tunnel-1']['left_outside_ip']
    ctx.instance.runtime_properties['peer_2_ip'] = config['tunnel-1']['left_outside_ip']
    print "peer_2_shared_secret: " + config['tunnel-1']['psk']
    ctx.instance.runtime_properties['peer_2_shared_secret'] = config['tunnel-1']['psk']
    print "peer_2_tunnel_ip: " + config['tunnel-1']['right_inside_ip']
    ctx.instance.runtime_properties['peer_2_tunnel_ip'] = config['tunnel-1']['right_inside_ip']
    peer_2_tunnel_peer = config['tunnel-1']['left_inside_ip']
    peer_2_tunnel_peer = peer_2_tunnel_peer[0:peer_2_tunnel_peer.find("/")]
    print "peer_2_tunnel_peer: " + peer_2_tunnel_peer
    ctx.instance.runtime_properties['peer_2_tunnel_peer'] = peer_2_tunnel_peer
    print "remote_as:  " + config['tunnel-0']['left_asn']
    ctx.instance.runtime_properties['remote_as'] = config['tunnel-0']['left_asn']


