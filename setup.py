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


from setuptools import setup

# Replace the place holders with values for your project

setup(

    # Do not use underscores in the openstack-simple name.
    name='aws_get_vpn_connection_info',

    version='0.1',
    author='Tomakh Konstantin',
    author_email='ktomakh',
    description='Get connection informa tion from AWS',

    # This must correspond to the actual packages in the openstack-simple.
    packages=['aws_get_vpn_connection_info'],

    license='Mirantis Inc. All rights reserved',
    zip_safe=False,
    install_requires=[
        'boto3'
    ]

)