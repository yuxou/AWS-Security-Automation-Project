import json, os, boto3, time

# === 환경 변수 ===
REGION = os.environ.get("REGION") or os.environ.get("AWS_REGION", "us-east-1")
ec2 = boto3.client("ec2", region_name=REGION)
WS_ENDPOINT = os.environ.get("WS_ENDPOINT")
CONNECTIONS_TABLE = os.environ.get("TABLE_NAME")

# === 리소스 ===
dynamodb = boto3.resource('dynamodb', region_name=REGION)
table = dynamodb.Table(CONNECTIONS_TABLE)

def get_api_gateway_client():
    """API Gateway Management API 클라이언트 (웹소켓 메시지 전송용)"""
    return boto3.client(
        'apigatewaymanagementapi',
        endpoint_url=f"{WS_ENDPOINT}",
        region_name=REGION
    )

def send_to_all_clients(message):
    """연결된 모든 WebSocket 클라이언트에게 메시지 전송"""
    api_client = get_api_gateway_client()
    connections = table.scan().get("Items", [])
    print(f"📡 Connected clients: {len(connections)}")

    for conn in connections:
        connection_id = conn["connectionId"]
        try:
            api_client.post_to_connection(
                ConnectionId=connection_id,
                Data=json.dumps(message).encode('utf-8')
            )
            print(f"✅ Sent to {connection_id}")
        except Exception as e:
            print(f"⚠️ Failed for {connection_id}: {e}")
            # 만료된 연결은 삭제
            table.delete_item(Key={"connectionId": connection_id})

def lambda_handler(event, context):
    detail = event.get("detail", {})
    region = event.get("region")
    principal = detail.get("userIdentity", {}).get("arn","unknown")
    eventName = detail.get("eventName")
    source = detail.get("eventSource")

    # ✅ 중요 서비스만 체크
    IMPORTANT = [
        "ec2.amazonaws.com","s3.amazonaws.com","iam.amazonaws.com",
        "lambda.amazonaws.com","rds.amazonaws.com","eks.amazonaws.com"
    ]
    if source not in IMPORTANT:
        return {"status":"ignore"}

    # ✅ DynamoDB에 baseline(평소 사용하는 리전 목록) 저장
    pk = f"baseline_regions#{principal}"
    ddb = boto3.client("dynamodb", region_name=REGION)

    try:
        r = ddb.get_item(TableName=CONNECTIONS_TABLE, Key={"connectionId": {"S": pk}})
        known_regions = json.loads(r.get("Item", {}).get("regions", {}).get("S", "[]"))
    except:
        known_regions = []

    # ✅ 평소 사용하지 않던 리전 감지
    if region not in known_regions:
        known_regions.append(region)
        ddb.put_item(
            TableName=CONNECTIONS_TABLE,
            Item={
                "connectionId": {"S": pk},
                "regions": {"S": json.dumps(known_regions)},
                "ttl": {"N": str(int(time.time()) + 60*60*24*30)}  # 30일 유지
            }
        )

        message = {
            "alert_type": "unusual_region_access",
            "principal": principal,
            "region": region,
            "event": eventName,
            "source": source,
            "baseline_regions": known_regions,
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        }
        send_to_all_clients(message)

    return {"status": "ok", "region": region}
