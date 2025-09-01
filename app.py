import os
import binascii
from datetime import datetime, timedelta
from typing import Dict, Optional, List

from flask import Flask, jsonify, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests

from data_pb2 import AccountPersonalShowInfo
from google.protobuf.json_format import MessageToDict
import uid_generator_pb2

app = Flask(__name__)

# ===============
# Configuration
# ===============
API_KEY = os.environ.get("API_KEY", "DANGERxINFO")
OWNER = os.environ.get("OWNER", "T.ME/DANGER_FF_LIKE")
TELEGRAM_GROUP = os.environ.get("TELEGRAM_GROUP", "T.ME/FREEFIRELIKES_DANGER")
TELEGRAM_CHANNEL = os.environ.get("TELEGRAM_CHANNEL", "T.ME/FREEFIRELIKESDANGER")

DEFAULT_KEY = os.environ.get("DEFAULT_KEY", "Yg&tc%DEuh6%Zc^8")
DEFAULT_IV = os.environ.get("DEFAULT_IV", "6oyZDr22E3ychjM%")

POST_TIMEOUT = 4
GET_TIMEOUT = 5
RETRIES_POST = 2
RETRIES_GET = 2
MAX_REGION_WORKERS = 3
JWT_LIFETIME_HOURS = 7

jwt_endpoints: Dict[str, str] = {
    "IND": "https://jwt-maker-danger.vercel.app/token?uid=4046927312&password=959197782F4D2645733E4C17B280E6599D4A2A63B9F0E14D10197F9E65A408E3",
    "AMERICAS": "https://jwt-maker-danger.vercel.app/token?uid=4105104823&password=C8926248580CA5D954F37475DC3E1A9931DAFA1075AF0F8C515515C3ED733B4A",
    "DEFAULT": "https://jwt-maker-danger.vercel.app/token?uid=4121314968&password=988EE85B638C2B4FDBDF83636C7D5A7917E0D5C4B8E6EB68A53CE82882BFF8D4"
}

api_endpoints: Dict[str, str] = {
    "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
    "BR":  "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    "US":  "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    "NA":  "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
    "DEFAULT": "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"
}

# Simple in-memory JWT cache. On serverless, this will be per cold-start.
jwt_token_cache: Dict[str, dict] = {}

# ========
# Helpers
# ========

def safe_message_to_dict(msg):
    """Wrapper to handle old/new protobuf versions safely."""
    try:
        return MessageToDict(msg, including_default_value_fields=True)
    except TypeError:
        return MessageToDict(msg)


def check_api_key():
    key = request.args.get('key') or request.headers.get('x-api-key')
    if key != API_KEY:
        return jsonify({
            "status": "error",
            "message": "Invalid API Key",
            "credits": OWNER,
            "telegram": {"group": TELEGRAM_GROUP, "channel": TELEGRAM_CHANNEL}
        }), 401
    return None


def encrypt_data(data_hex: str, key: str, iv: str) -> str:
    cipher = AES.new(key.encode()[:16], AES.MODE_CBC, iv.encode()[:16])
    padded = pad(bytes.fromhex(data_hex), AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded)).decode()


def safe_get(url: str, timeout: int = GET_TIMEOUT, retries: int = RETRIES_GET):
    last_err = None
    for i in range(retries):
        try:
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp
        except Exception as e:
            last_err = e
    if last_err:
        raise last_err


def safe_post(url: str, headers: dict, data: bytes, timeout: int = POST_TIMEOUT, retries: int = RETRIES_POST):
    last_err = None
    for i in range(retries):
        try:
            resp = requests.post(url, headers=headers, data=data, timeout=timeout)
            resp.raise_for_status()
            return resp
        except Exception as e:
            last_err = e
    if last_err:
        raise last_err


def get_regions_to_try(requested_region: Optional[str]) -> List[str]:
    if requested_region:
        r = requested_region.upper()
        rest = ["IND", "US", "DEFAULT"]
        return [r] + [x for x in rest if x != r]
    return ["IND", "US", "DEFAULT"]


def get_jwt_token(region: str) -> Optional[str]:
    region_key = "AMERICAS" if region in ["BR", "US", "SAC", "NA"] else region

    token_data = jwt_token_cache.get(region_key)
    if token_data and token_data['expiry'] > datetime.utcnow():
        return token_data['token']

    try:
        url = jwt_endpoints.get(region_key, jwt_endpoints["DEFAULT"])
        resp = safe_get(url)
        data = resp.json()
        token = data.get("token") or data.get("jwt")
        if token:
            expiry_time = datetime.utcnow() + timedelta(hours=JWT_LIFETIME_HOURS)
            jwt_token_cache[region_key] = {'token': token, 'expiry': expiry_time}
            return token
    except Exception:
        return None

    return None


def query_game_api(encrypted_hex: str, region: str) -> bytes:
    token = get_jwt_token(region)
    if not token:
        raise RuntimeError(f"Failed to get JWT token for {region}")

    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB50',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    url = api_endpoints.get(region, api_endpoints["DEFAULT"])
    resp = safe_post(url, headers=headers, data=bytes.fromhex(encrypted_hex))
    return resp.content


def try_region_once(request_hex: str, enc_key: str, enc_iv: str, region: str) -> dict:
    try:
        # Encrypt and query game API
        encrypted = encrypt_data(request_hex, enc_key, enc_iv)
        raw = query_game_api(encrypted, region)

        # Parse protobuf
        msg = AccountPersonalShowInfo()
        msg.ParseFromString(raw)

        # Convert to dict safely
        result_dict = safe_message_to_dict(msg)

        # Prime Level handling (always include)
        if hasattr(msg, "basic_info"):
            try:
                if msg.basic_info.HasField("prime_level"):
                    prime_info = safe_message_to_dict(msg.basic_info.prime_level)
                else:
                    prime_info = {"primeLevel": 0}  # default if not provided

                if "basicInfo" not in result_dict:
                    result_dict["basicInfo"] = {}
                result_dict["basicInfo"]["primeLevelInfo"] = prime_info
            except Exception as pe:
                print(f"[DEBUG] Prime parse error in region {region}: {pe}")
                if "basicInfo" not in result_dict:
                    result_dict["basicInfo"] = {}
                result_dict["basicInfo"]["primeLevelInfo"] = {"primeLevel": 0}

        return result_dict

    except Exception as e:
        print(f"[DEBUG] Error inside try_region_once for {region}: {e}")
        return {
            "status": "error",
            "region": region,
            "message": f"Failed to process region {region}",
            "error": str(e)
        }

@app.route('/ping')
def ping():
    return {"status": "ok", "message": "Server is awake"}, 200


@app.route('/accinfo', methods=['GET'])
def get_player_info():
    if error := check_api_key():
        return error

    uid = request.args.get('uid', '').strip()
    if not uid.isdigit():
        return jsonify({"status": "error", "message": "Valid UID required", "credits": OWNER}), 400

    enc_key = request.args.get('enc_key', DEFAULT_KEY)
    enc_iv = request.args.get('enc_iv', DEFAULT_IV)
    region_req = request.args.get('region', '').strip().upper() or None

    pb_request = uid_generator_pb2.uid_generator()
    pb_request.saturn_ = int(uid)
    pb_request.garena = 1
    request_hex = binascii.hexlify(pb_request.SerializeToString()).decode()

    regions = get_regions_to_try(region_req)

    last_error = None
    for reg in regions:
        try:
            result = try_region_once(request_hex, enc_key, enc_iv, reg)
            result.update({
                "credits": OWNER,
                "telegram": {"group": TELEGRAM_GROUP, "channel": TELEGRAM_CHANNEL},
                "api": API_KEY,
                "region": reg
            })
            return jsonify(result)
        except Exception as e:
            last_error = str(e)

    return jsonify({
        "status": "error",
        "message": "Player not found or all regions unreachable",
        "error": last_error,
        "credits": OWNER,
        "contact": TELEGRAM_GROUP
    }), 404
