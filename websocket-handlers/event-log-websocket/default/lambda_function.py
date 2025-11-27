import json

def lambda_handler(event, context):

    body = event.get('body', '')

    if 'ping' in str(body):
        print("DEBUG: Ping detected, returning Pong.")
        return {
            "statusCode": 200,
            "body": "pong"
        }
  
    print("DEBUG: $default invoked")
    
    return {
        "statusCode": 200,
        "body": "pong"  
    }