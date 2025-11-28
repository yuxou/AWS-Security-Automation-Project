import os, boto3, json, time
from botocore.exceptions import ClientError

EVENT_DDB_TABLE = os.environ['EVENT_CONNECTIONS_TABLE']
REMED_DDB_TABLE = os.environ['REMED_CONNECTIONS_TABLE']
EVENT_ENDPOINT = os.environ['EVENT_API_GW_ENDPOINT']
REMED_ENDPOINT = os.environ['REMED_API_GW_ENDPOINT']
HISTORY_DDB_TABLE = os.environ['HISTORY_CONNECTIONS_TABLE']
HISTORY_ENDPOINT = os.environ['HISTORY_API_GW_ENDPOINT']

dynamodb = boto3.resource('dynamodb')

def send_ping(connection_id, endpoint):
    apigw_management = boto3.client('apigatewaymanagementapi', endpoint_url=f"https://{endpoint}")
    try:
        apigw_management.post_to_connection(
            ConnectionId=connection_id,
            Data=json.dumps({"type": "ping", "timestamp": int(time.time() * 1000)})
        )
        return "OK" 
    except apigw_management.exceptions.GoneException:
        print(f"Connection {connection_id} is gone on {endpoint}")
        return "GONE" 
    except Exception as e:
        print(f"Error sending to {connection_id}: {e}")
        return "ERROR"

def get_connections_and_ping(table_name, endpoint):
    table = dynamodb.Table(table_name)
    
    try:
        response = table.scan(ProjectionExpression='connectionId')
        items = response.get('Items', [])
    except Exception as e:
        print(f"Scan error on {table_name}: {e}")
        return 0

    connection_ids = [item['connectionId'] for item in items]
    successful_pings = 0
    
    for connection_id in connection_ids:
        status = send_ping(connection_id, endpoint)
        
        if status == "OK":
            successful_pings += 1
        elif status == "GONE":
            try: 
                table.delete_item(Key={'connectionId': connection_id})
                print(f"Deleted stale connection: {connection_id}")
            except: pass

    return successful_pings

def lambda_handler(event, context):
    event_count = get_connections_and_ping(EVENT_DDB_TABLE, EVENT_ENDPOINT)
    remed_count = get_connections_and_ping(REMED_DDB_TABLE, REMED_ENDPOINT)
    history_count = get_connections_and_ping(HISTORY_DDB_TABLE, HISTORY_ENDPOINT)
    
    return {
        'statusCode': 200,
        'body': f"Pings Sent - Event: {event_count}, Remed: {remed_count}, History: {history_count}"
    }
