import os
import sys
import json
import time
import select
import signal
import termios
import struct
import fcntl
import threading
import subprocess
import pty
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import yaml
import boto3
import botocore.exceptions
from collections import defaultdict

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Store active sessions
sessions = {}  # Key: session_id, Value: SSMSession object

class SSMSession:
    def __init__(self, instance_id, session_id):
        self.instance_id = instance_id
        self.session_id = session_id
        self.process = None
        self.master_fd = None
        self.running = False
        self.output_thread = None

    def start_session(self):
        try:
            # Get AWS configuration and check instance status first
            config = get_instance_config(self.instance_id)
            if not config:
                print(f"No AWS configuration found for instance {self.instance_id}")
                return False
                
            aws_profile = config['aws_profile']
            aws_region = config['region']
                
            # Check if instance is connected before attempting to start session
            if not check_instance_status(self.instance_id, aws_profile, aws_region):
                print(f"Instance {self.instance_id} is not connected to SSM")
                return False
            
            master_fd, slave_fd = pty.openpty()
            self.master_fd = master_fd
            
            # Get current environment and update AWS settings
            env = os.environ.copy()
            env['AWS_PROFILE'] = aws_profile
            env['AWS_DEFAULT_REGION'] = aws_region
            print(f"Using AWS_PROFILE={aws_profile}, AWS_DEFAULT_REGION={aws_region} for instance {self.instance_id}")
            
            # Start the SSM session with the updated environment
            command = ["aws", "ssm", "start-session", "--target", self.instance_id]
            self.process = subprocess.Popen(
                command,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                preexec_fn=os.setsid,
                env=env
            )
            
            os.close(slave_fd)  # Close slave fd after process started
            
            self.running = True
            self.output_thread = threading.Thread(target=self.read_output)
            self.output_thread.daemon = True
            self.output_thread.start()
            
            return True
        except Exception as e:
            print(f"Error starting session: {str(e)}")
            self.close()
            return False

    def read_output(self):
        try:
            while self.running and self.process and self.process.poll() is None:
                try:
                    r, w, e = select.select([self.master_fd], [], [], 0.1)
                    if self.master_fd in r:
                        try:
                            data = os.read(self.master_fd, 1024)
                            if data:
                                text = data.decode('utf-8', errors='replace')
                                if 'Starting session with SessionId' in text:
                                    print(f"Session established for {self.instance_id} (session {self.session_id})")
                                elif 'Exiting session with sessionId' in text:
                                    print(f"Session disconnected for {self.instance_id} (session {self.session_id})")
                                socketio.emit('terminal_output', {
                                    'instance_id': self.instance_id,
                                    'session_id': self.session_id,
                                    'output': text
                                })
                            else:
                                break
                        except (OSError, IOError) as e:
                            if e.errno == 9:  # Bad file descriptor
                                break
                            print(f"Error reading from terminal: {str(e)}")
                            break
                except select.error:
                    break
        except Exception as e:
            print(f"Error in output thread: {str(e)}")
        finally:
            # Log disconnection if we haven't already
            if self.running:
                socketio.emit('terminal_output', {
                    'instance_id': self.instance_id, 
                    'session_id': self.session_id,
                    'output': f"\r\nSession disconnected for {self.instance_id}\r\n"
                })
            self.running = False

    def write_input(self, data):
        if self.master_fd is not None and self.running:
            try:
                os.write(self.master_fd, data.encode())
            except (OSError, IOError) as e:
                print(f"Error writing to terminal: {str(e)}")
                self.close()

    def resize_terminal(self, rows, cols):
        if self.master_fd is not None and self.running:
            try:
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            except (OSError, IOError) as e:
                print(f"Error resizing terminal: {str(e)}")

    def close(self):
        self.running = False
        
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except (OSError, IOError):
                pass  # Ignore errors on close
            self.master_fd = None
        
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=1)  # Wait for process to terminate
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            except Exception as e:
                print(f"Error terminating process: {str(e)}")
            self.process = None
        
        if (self.output_thread and 
            self.output_thread.is_alive() and 
            threading.current_thread() != self.output_thread):
            try:
                self.output_thread.join(timeout=1)
            except RuntimeError:
                pass  # Ignore if we can't join the thread
            self.output_thread = None

def get_instance_config(instance_id):
    try:
        with open('instances_list.yaml', 'r') as file:
            data = yaml.safe_load(file)
            for customer, customer_data in data.items():
                for env_name, instances in customer_data.get('instances', {}).items():
                    if isinstance(instances, list):  # Direct list of instances
                        for instance in instances:
                            if instance.get('instance_id') == instance_id:
                                return {
                                    'aws_profile': customer_data.get('aws_profile'),
                                    'region': customer_data.get('region')
                                }
                    else:  # Nested environment structure
                        for instance in instances:
                            if instance.get('instance_id') == instance_id:
                                return {
                                    'aws_profile': customer_data.get('aws_profile'),
                                    'region': customer_data.get('region')
                                }
        print(f"Warning: No configuration found for instance {instance_id}")
        return None
    except Exception as e:
        print(f"Error finding instance configuration: {str(e)}")
        return None

def check_instance_status(instance_id, profile, region):
    try:
        # Use the specified AWS profile and region
        session = boto3.Session(profile_name=profile, region_name=region)
        ssm_client = session.client('ssm')
        
        # Check instance connection status
        response = ssm_client.describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
        )
        
        if response['InstanceInformationList']:
            instance_info = response['InstanceInformationList'][0]
            status = instance_info['PingStatus']
            print(f"Instance {instance_id} status: {status} (region: {region})")
            return status == 'Online'
        else:
            print(f"Instance {instance_id} not found in SSM (region: {region})")
            return False
            
    except botocore.exceptions.ClientError as e:
        print(f"AWS Error checking instance status: {str(e)}")
        return False
    except Exception as e:
        print(f"Error checking instance status: {str(e)}")
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/instances')
def get_instances():
    try:
        print("Loading instances from YAML...")
        with open('instances_list.yaml', 'r') as file:
            data = yaml.safe_load(file)
        
        print(f"Loaded YAML data: {data}")
        
        tree = []
        for customer, customer_data in data.items():
            customer_node = {
                'name': customer,
                'type': 'customer',
                'environments': []
            }
            
            if 'instances' in customer_data:
                environments = customer_data['instances']
                for env_name, instances in environments.items():
                    env_node = {
                        'name': env_name,
                        'type': 'environment',
                        'instances': []
                    }
                    
                    for instance in instances:
                        instance_node = {
                            'name': instance['name'],
                            'id': instance['instance_id'],
                            'type': 'instance'
                        }
                        env_node['instances'].append(instance_node)
                    
                    customer_node['environments'].append(env_node)
            
            tree.append(customer_node)
        
        return jsonify(tree)
    except Exception as e:
        print(f"Error loading instances: {str(e)}")
        return jsonify([])

@app.route('/scan-instances')
def scan_instances():
    """
    Scan AWS EC2 instances and organize them by TAG1 (root) and TAG2 (branch)
    """
    try:
        # Get environment variables for tag names
        tag1_name = os.environ.get('TAG1', 'Customer')  # Default to 'Customer' if not set
        tag2_name = os.environ.get('TAG2', 'Environment')  # Default to 'Environment' if not set
        
        print(f"Scanning instances with TAG1={tag1_name}, TAG2={tag2_name}")
        
        # Get all AWS profiles and regions from the YAML file
        profiles_regions = get_aws_profiles_and_regions()
        
        all_instances = []
        
        # Scan instances from all configured AWS profiles and regions
        for profile, region in profiles_regions:
            try:
                instances = fetch_ec2_instances(profile, region, tag1_name, tag2_name)
                all_instances.extend(instances)
                print(f"Found {len(instances)} instances in profile {profile}, region {region}")
            except Exception as e:
                print(f"Error scanning profile {profile}, region {region}: {str(e)}")
                continue
        
        # Organize instances by TAG1 and TAG2
        tree = organize_instances_by_tags(all_instances, tag1_name, tag2_name)
        
        return jsonify(tree)
    except Exception as e:
        print(f"Error scanning instances: {str(e)}")
        return jsonify({'error': str(e)}), 500

def get_aws_profiles_and_regions():
    """
    Extract AWS profiles and regions from the instances_list.yaml file
    """
    profiles_regions = set()
    try:
        with open('instances_list.yaml', 'r') as file:
            data = yaml.safe_load(file)
        
        for customer_data in data.values():
            if isinstance(customer_data, dict):
                profile = customer_data.get('aws_profile')
                region = customer_data.get('region')
                if profile and region:
                    profiles_regions.add((profile, region))
    except Exception as e:
        print(f"Error reading instances_list.yaml: {str(e)}")
        # Fallback to default
        profiles_regions.add(('default', 'us-east-1'))
    
    return list(profiles_regions)

def fetch_ec2_instances(aws_profile, aws_region, tag1_name, tag2_name):
    """
    Fetch EC2 instances from AWS with their tags and metadata
    """
    try:
        # Create boto3 session with the specified profile
        session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
        ec2 = session.client('ec2')
        sts = session.client('sts')
        
        # Get AWS Account ID
        account_info = sts.get_caller_identity()
        account_id = account_info['Account']
        
        # Describe all instances
        response = ec2.describe_instances()
        
        instances = []
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                # Extract tags
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                
                # Get instance metadata
                instance_data = {
                    'instance_id': instance['InstanceId'],
                    'name': tags.get('Name', instance['InstanceId']),
                    'state': instance['State']['Name'],
                    'platform': instance.get('Platform', 'linux'),  # 'windows' or defaults to 'linux'
                    'instance_type': instance['InstanceType'],
                    'aws_profile': aws_profile,
                    'region': aws_region,
                    'account_id': account_id,
                    'tags': tags,
                    tag1_name.lower(): tags.get(tag1_name, 'Unknown'),
                    tag2_name.lower(): tags.get(tag2_name, 'Unknown')
                }
                
                instances.append(instance_data)
        
        return instances
    except Exception as e:
        print(f"Error fetching instances from {aws_profile}/{aws_region}: {str(e)}")
        return []

def organize_instances_by_tags(instances, tag1_name, tag2_name):
    """
    Organize instances into a tree structure based on AWS Account ID, Region, then TAG1 and TAG2
    """
    # Group instances by Account ID first, then Region, then TAG1, then TAG2
    account_groups = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(list))))
    
    for instance in instances:
        account_id = instance.get('account_id', 'Unknown')
        region = instance.get('region', 'Unknown')
        tag1_value = instance.get(tag1_name.lower(), 'Unknown')
        tag2_value = instance.get(tag2_name.lower(), 'Unknown')
        account_groups[account_id][region][tag1_value][tag2_value].append(instance)
    
    # Build tree structure
    tree = []
    
    for account_id, region_groups in account_groups.items():
        # Create account-level node
        account_node = {
            'name': f'AWS Account: {account_id}',
            'type': 'account',
            'regions': []
        }
        
        for region, tag1_groups in region_groups.items():
            # Create region-level node
            region_node = {
                'name': f'Region: {region}',
                'type': 'region',
                'customers': []
            }
            
            for tag1_value, tag2_groups in tag1_groups.items():
                tag1_node = {
                    'name': tag1_value,
                    'type': 'customer',
                    'environments': []
                }
                
                for tag2_value, instances_list in tag2_groups.items():
                    tag2_node = {
                        'name': tag2_value,
                        'type': 'environment',
                        'instances': []
                    }
                    
                    for instance in instances_list:
                        instance_node = {
                            'name': instance['name'],
                            'id': instance['instance_id'],
                            'type': 'instance',
                            'state': instance['state'],
                            'platform': instance['platform'],
                            'instance_type': instance['instance_type'],
                            'aws_profile': instance['aws_profile'],
                            'region': instance['region'],
                            'account_id': instance['account_id']
                        }
                        tag2_node['instances'].append(instance_node)
                    
                    tag1_node['environments'].append(tag2_node)
                
                region_node['customers'].append(tag1_node)
            
            account_node['regions'].append(region_node)
        
        tree.append(account_node)
    
    return tree

@app.route('/save-scanned-instances', methods=['POST'])
def save_scanned_instances():
    """
    Save scanned instances to the instances_list.yaml file
    """
    try:
        # Get environment variables for tag names
        tag1_name = os.environ.get('TAG1', 'Customer')
        tag2_name = os.environ.get('TAG2', 'Environment')
        
        # Get all AWS profiles and regions from the YAML file
        profiles_regions = get_aws_profiles_and_regions()
        
        all_instances = []
        
        # Scan instances from all configured AWS profiles and regions
        for profile, region in profiles_regions:
            try:
                instances = fetch_ec2_instances(profile, region, tag1_name, tag2_name)
                all_instances.extend(instances)
            except Exception as e:
                print(f"Error scanning profile {profile}, region {region}: {str(e)}")
                continue
        
        # Convert to YAML format
        yaml_data = convert_instances_to_yaml_format(all_instances, tag1_name, tag2_name)
        
        # Save to file
        with open('instances_list.yaml', 'w') as file:
            yaml.dump(yaml_data, file, default_flow_style=False, sort_keys=False)
        
        return jsonify({'success': True, 'message': 'Instances saved successfully'})
    except Exception as e:
        print(f"Error saving instances: {str(e)}")
        return jsonify({'error': str(e)}), 500

def convert_instances_to_yaml_format(instances, tag1_name, tag2_name):
    """
    Convert scanned instances to the YAML format expected by the application
    Note: YAML format doesn't support account segregation, so we'll group by TAG1 and TAG2
    but add account info as comments
    """
    yaml_data = {}
    
    # Group instances by TAG1 and TAG2 (ignoring account for YAML compatibility)
    tag1_groups = defaultdict(lambda: defaultdict(list))
    
    for instance in instances:
        tag1_value = instance.get(tag1_name.lower(), 'Unknown')
        tag2_value = instance.get(tag2_name.lower(), 'Unknown')
        tag1_groups[tag1_value][tag2_value].append(instance)
    
    # Convert to YAML structure
    for tag1_value, tag2_groups in tag1_groups.items():
        # Use the first instance to get AWS profile and region for this group
        first_instance = next(iter(next(iter(tag2_groups.values()))))
        
        # Create a unique key that includes account info if multiple accounts exist
        account_id = first_instance.get('account_id', 'Unknown')
        yaml_key = f"{tag1_value}_{account_id}" if len(set(inst.get('account_id') for inst in instances)) > 1 else tag1_value
        
        yaml_data[yaml_key] = {
            'region': first_instance['region'],
            'aws_profile': first_instance['aws_profile'],
            'account_id': account_id,  # Add account ID to YAML
            'instances': {}
        }
        
        for tag2_value, instances_list in tag2_groups.items():
            yaml_data[yaml_key]['instances'][tag2_value] = []
            
            for instance in instances_list:
                yaml_data[yaml_key]['instances'][tag2_value].append({
                    'name': instance['name'],
                    'instance_id': instance['instance_id']
                })
    
    return yaml_data

@socketio.on('connect')
def handle_connect():
    # Just log the connection, don't start any sessions
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')
    # Clean up any existing sessions for this client
    for session_id, session in list(sessions.items()):
        try:
            session.close()
            del sessions[session_id]
        except Exception as e:
            print(f'Error cleaning up session {session_id}: {e}')

@socketio.on('start_session')
def handle_start_session(data):
    instance_id = data.get('instance_id')
    session_id = data.get('session_id')
    
    if not instance_id or not session_id:
        emit('session_error', {'error': 'Invalid instance or session ID'})
        return

    try:
        session = SSMSession(instance_id, session_id)
        if session.start_session():
            sessions[session_id] = session
            emit('session_started', {
                'instance_id': instance_id,
                'session_id': session_id
            })
        else:
            emit('session_error', {
                'instance_id': instance_id,
                'session_id': session_id,
                'error': 'Failed to start session'
            })
    except Exception as e:
        emit('session_error', {
            'instance_id': instance_id,
            'session_id': session_id,
            'error': str(e)
        })

@socketio.on('terminal_input')
def handle_terminal_input(data):
    session_id = data.get('session_id')
    input_data = data.get('input')
    
    if not session_id or not input_data:
        return
        
    session = sessions.get(session_id)
    if session:
        session.write_input(input_data)

@socketio.on('terminal_interrupt')
def handle_terminal_interrupt(data):
    session_id = data.get('session_id')
    if session_id in sessions:
        session = sessions[session_id]
        # Send Ctrl+C signal to the process group
        if session.process:
            try:
                os.killpg(os.getpgid(session.process.pid), signal.SIGINT)
            except ProcessLookupError:
                pass

@socketio.on('terminal_resize')
def handle_terminal_resize(data):
    session_id = data.get('session_id')
    rows = data.get('rows')
    cols = data.get('cols')
    
    if not all([session_id, rows, cols]):
        return
        
    session = sessions.get(session_id)
    if session:
        session.resize_terminal(rows, cols)

@socketio.on('close_session')
def handle_close_session(data):
    session_id = data.get('session_id')
    if session_id in sessions:
        session = sessions[session_id]
        session.close()
        del sessions[session_id]

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
