from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import struct

app = Flask(__name__)
CORS(app)

# Helper to parse central directory entries from ZIP EOCD remote fetch
def parse_central_directory(data):
    files = []
    signature = b'\x50\x4b\x01\x02'  # Central directory file header
    pos = 0
    while True:
        pos = data.find(signature, pos)
        if pos == -1:
            break
        try:
            filename_len = struct.unpack('<H', data[pos+28:pos+30])[0]
            extra_len = struct.unpack('<H', data[pos+30:pos+32])[0]
            comment_len = struct.unpack('<H', data[pos+32:pos+34])[0]
            filename = data[pos+46:pos+46+filename_len].decode('utf-8')
            comp_size = struct.unpack('<I', data[pos+20:pos+24])[0]
            uncomp_size = struct.unpack('<I', data[pos+24:pos+28])[0]
            local_header_offset = struct.unpack('<I', data[pos+42:pos+46])[0]
            compression = struct.unpack('<H', data[pos+10:pos+12])[0]
            files.append({
                'filename': filename,
                'compressed_size': comp_size,
                'uncompressed_size': uncomp_size,
                'local_header_offset': local_header_offset,
                'compression': compression,
            })
            pos += 46 + filename_len + extra_len + comment_len
        except Exception:
            break
    return files

# Get byte range to fetch EOCD from remote ZIP
def get_eocd_range(total_size):
    read_size = min(66000, total_size)
    return total_size - read_size, total_size - 1

@app.route("/api/inspect", methods=["POST"])
def inspect_zip():
    data = request.json
    url = data.get('url')
    cookies = data.get('cookies', '')
    user_agent = data.get('userAgent', '')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    headers = {}
    if cookies:
        headers['Cookie'] = cookies
    if user_agent:
        headers['User-Agent'] = user_agent

    # Step 1: Get content length
    head_resp = requests.head(url, headers=headers)
    if head_resp.status_code != 200 or 'Content-Length' not in head_resp.headers:
        return jsonify({'error': 'Failed to get content length'}), 400
    total_size = int(head_resp.headers['Content-Length'])

    # Step 2: Get EOCD
    start, end = get_eocd_range(total_size)
    headers['Range'] = f'bytes={start}-{end}'
    range_resp = requests.get(url, headers=headers)
    if range_resp.status_code not in [200, 206]:
        return jsonify({'error': 'Failed to download EOCD range'}), 400
    data_bytes = range_resp.content

    # Step 3: Find EOCD
    eocd_signature = b'\x50\x4b\x05\x06'
    eocd_pos = data_bytes.rfind(eocd_signature)
    if eocd_pos == -1:
        return jsonify({'error': 'EOCD not found in ZIP file'}), 400

    # Step 4: Parse EOCD
    cd_size = struct.unpack('<I', data_bytes[eocd_pos+12:eocd_pos+16])[0]
    cd_offset = struct.unpack('<I', data_bytes[eocd_pos+16:eocd_pos+20])[0]

    # Step 5: Fetch central directory
    cd_start = cd_offset
    cd_end = cd_offset + cd_size - 1
    headers['Range'] = f'bytes={cd_start}-{cd_end}'
    cd_resp = requests.get(url, headers=headers)
    if cd_resp.status_code not in [200, 206]:
        return jsonify({'error': 'Failed to download central directory'}), 400
    cd_data = cd_resp.content

    # Step 6: Parse directory
    files = parse_central_directory(cd_data)
    return jsonify({'files': files})

@app.route("/")
def home():
    return jsonify({"message": "PicknFetch backend is running."})

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
