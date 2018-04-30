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


from cloudify import ctx
import boto3
from collections import OrderedDict
import xmltodict
from cloudify.exceptions import NonRecoverableError


from cloudify.decorators import operation

#input REGION NAME
regionName = ''
#input CustomerGatewayId
customerGatewayId = ''
#input AWS Access Key ID
awsAccessKeyId= ''
#input AWS Secret Key
awsSecretAccessKey= ''

@operation
def start(**kwargs):
    properties = ctx.node.properties
    ConnectionInfo = properties.get('connection_infomation', {})
    ConnectionInfo.update(kwargs.get('connection_infomation', {}))
    global customerGatewayId
    customerGatewayId = ConnectionInfo.get('customer_gateway_id')
    ctx.logger.info('customer_gateway_id = ' + customerGatewayId)

    if(customerGatewayId == ''):
        ctx.logger.info('Customer gateway id not set ')
        raise NonRecoverableError("Customer gateway id not set")

    global awsAccessKeyId
    awsAccessKeyId = ConnectionInfo.get('aws_access_key_id')
    ctx.logger.info('AWS Access Key Id = ' + awsAccessKeyId)

    global awsSecretAccessKey
    awsSecretAccessKey = ConnectionInfo.get('aws_secret_access_key')
    ctx.logger.info('AWS Secret Access Key = ' + awsSecretAccessKey)

    global regionName
    regionName = ConnectionInfo.get('ec2_region_name')
    ctx.logger.info('AWS Region Name = ' + regionName)

    try:
        get_connection_config()
    except WaitInterval:
        ctx.logger.info('Catch wait interwal')
        return ctx.operation.retry(message='Still waiting for connection id = ' + ctx.node.properties['customer_gateway_id'])


class WaitInterval(Exception):
   pass


def get_vpn_config(ec2, regions):
    global_config = OrderedDict()
    mark = iter(range(100, 4000, 100))
    for region in regions:
        ctx.logger.info('Looking in AWS Region %s' % region)
        response = ec2.describe_vpn_connections()
        local_config = parse_vpn_response(response, mark)
        global_config.update(local_config)
    return global_config

def parse_vpn_response(response, mark):
    config = OrderedDict()
    find = False
    for connection in response['VpnConnections']:
        if connection['CustomerGatewayId'] != customerGatewayId:
            continue

        ctx.logger.info("Customer Gateway Id Connection state = " + connection['State'])

        if connection['State'] == 'pending':
            ctx.operation.retry(message='Still waiting for the VM to start..')
            raise WaitInterval

        if connection['State'] != 'available':
            continue

        find = True # necessary AWS connection finded

        vpn_id = connection['VpnConnectionId']
        config = OrderedDict()
        items = connection.items()

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
        ctx.logger.info('No available connection for AWS Customer Gateway Id' + customerGatewayId)
        raise WaitInterval

    return config


def get_connection_config():
    ctx.logger.info("AWS Access Key Id = " + awsAccessKeyId)
    ctx.logger.info("AWS Secret Access Key = " + awsSecretAccessKey)
    ctx.logger.info("Region Name = " + regionName)
    ec2 = boto3.client('ec2',
                       aws_access_key_id=awsAccessKeyId,
                       aws_secret_access_key=awsSecretAccessKey,
                       region_name=regionName
                       )
    regions_list = []
    regions_list.append(regionName)
    config = get_vpn_config(ec2, regions_list)

    ctx.logger.info("peer_1_ip: " + config['tunnel-0']['left_outside_ip'])
    ctx.instance.runtime_properties['peer_1_ip'] = config['tunnel-0']['left_outside_ip']
    ctx.logger.info("peer_1_shared_secret: " + config['tunnel-0']['psk'])
    ctx.instance.runtime_properties['peer_1_shared_secret'] = config['tunnel-0']['psk']
    ctx.logger.info("peer_1_tunnel_ip: " + config['tunnel-0']['right_inside_ip'])
    ctx.instance.runtime_properties['peer_1_tunnel_ip'] = config['tunnel-0']['right_inside_ip']
    peer_1_tunnel_peer = config['tunnel-0']['left_inside_ip']
    ctx.instance.runtime_properties['peer_1_tunnel_peer'] = config['tunnel-0']['left_inside_ip']
    peer_1_tunnel_peer = peer_1_tunnel_peer[0:peer_1_tunnel_peer.find("/")]
    ctx.logger.info("peer_1_tunnel_peer: " + peer_1_tunnel_peer)
    ctx.instance.runtime_properties['peer_1_tunnel_peer'] = peer_1_tunnel_peer
    ctx.logger.info("peer_2_ip: " + config['tunnel-1']['left_outside_ip'])
    ctx.instance.runtime_properties['peer_2_ip'] = config['tunnel-1']['left_outside_ip']
    ctx.logger.info("peer_2_shared_secret: " + config['tunnel-1']['psk'])
    ctx.instance.runtime_properties['peer_2_shared_secret'] = config['tunnel-1']['psk']
    ctx.logger.info("peer_2_tunnel_ip: " + config['tunnel-1']['right_inside_ip'])
    ctx.instance.runtime_properties['peer_2_tunnel_ip'] = config['tunnel-1']['right_inside_ip']
    peer_2_tunnel_peer = config['tunnel-1']['left_inside_ip']
    peer_2_tunnel_peer = peer_2_tunnel_peer[0:peer_2_tunnel_peer.find("/")]
    ctx.logger.info("peer_2_tunnel_peer: " + peer_2_tunnel_peer)
    ctx.instance.runtime_properties['peer_2_tunnel_peer'] = peer_2_tunnel_peer
    ctx.logger.info("remote_as:  " + config['tunnel-0']['left_asn'])
    ctx.instance.runtime_properties['remote_as'] = config['tunnel-0']['left_asn']


