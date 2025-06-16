from flask import Flask, request, jsonify, send_file, abort, Response
from flask_cors import CORS
import requests
import io
import struct

app = Flask(__name__)

from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["https://frontend-one-sand.vercel.app/"])

# Helper to parse central directory entries from ZIP EOCD remote fetch
def parse_central_directory(data):
    files = []
    # Zip Central Directory header signature
    signature = b'\x50\x4b\x01\x02'
    pos = 0
    while True:
        pos = data.find(signature, pos)
        if pos == -1:
            break
        # Parse central directory file header (46 bytes fixed + variable)
        # Offsets based on ZIP spec
        # https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
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

# Helper to get EOCD offset and size for remote ZIP
def get_eocd_range(total_size):
    # EOCD size max 65557 bytes (max comment size 65535 + 22 bytes EOCD)
    # We request last 66 KB approx to find EOCD
    read_size = min(66000, total_size)
    return total_size - read_size, total_size - 1

@app.route('/api/inspect', methods=['POST'])
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

    # Step 1: HEAD to get content length
    head_resp = requests.head(url, headers=headers)
    if head_resp.status_code != 200 or 'Content-Length' not in head_resp.headers:
        return jsonify({'error': 'Failed to get content length'}), 400
    total_size = int(head_resp.headers['Content-Length'])

    # Step 2: Download EOCD from end of file
    start, end = get_eocd_range(total_size)
    headers['Range'] = f'bytes={start}-{end}'
    range_resp = requests.get(url, headers=headers)
    if range_resp.status_code not in [200, 206]:
        return jsonify({'error': 'Failed to download EOCD range'}), 400
    data_bytes = range_resp.content

    # Step 3: Find EOCD signature 0x06054b50 from the end
    eocd_signature = b'\x50\x4b\x05\x06'
    eocd_pos = data_bytes.rfind(eocd_signature)
    if eocd_pos == -1:
        return jsonify({'error': 'EOCD not found in ZIP file'}), 400

    # Step 4: Parse EOCD to get central directory offset and size
    cd_size = struct.unpack('<I', data_bytes[eocd_pos+12:eocd_pos+16])[0]
    cd_offset = struct.unpack('<I', data_bytes[eocd_pos+16:eocd_pos+20])[0]

    # Step 5: Download Central Directory range
    cd_start = cd_offset
    cd_end = cd_offset + cd_size - 1
    headers['Range'] = f'bytes={cd_start}-{cd_end}'
    cd_resp = requests.get(url, headers=headers)
    if cd_resp.status_code not in [200, 206]:
        return jsonify({'error': 'Failed to download central directory'}), 400
    cd_data = cd_resp.content

    # Step 6: Parse central directory entries
    files = parse_central_directory(cd_data)

    return jsonify({'files': files})

@app.route('/api/download', methods=['POST'])
def download_file():
    data = request.json
    url = data.get('url')
    filename = data.get('filename')
    offset = data.get('offset')
    comp_size = data.get('comp_size')
    compression = data.get('compression')
    cookies = data.get('cookies', '')
    user_agent = data.get('userAgent', '')

    if not all([url, filename, offset, comp_size]) :
        return jsonify({'error': 'Missing required parameters'}), 400

    headers = {}
    if cookies:
        headers['Cookie'] = cookies
    if user_agent:
        headers['User-Agent'] = user_agent

    # Download the local file header + compressed data
    # Local file header is typically 30 bytes + filename + extra field
    # To simplify, download from local header offset + compressed size + 100 bytes buffer
    # We parse local file header to get exact header size and data start

    range_start = offset
    range_end = offset + comp_size + 100  # extra buffer

    headers['Range'] = f'bytes={range_start}-{range_end}'
    resp = requests.get(url, headers=headers, stream=True)
    if resp.status_code not in [200, 206]:
        return jsonify({'error': 'Failed to download file data'}), 400

    # Read local file header
    content = resp.raw.read(30)
    if content[0:4] != b'\x50\x4b\x03\x04':
        return jsonify({'error': 'Invalid local file header'}), 400
    fname_len = struct.unpack('<H', content[26:28])[0]
    extra_len = struct.unpack('<H', content[28:30])[0]

    header_total_size = 30 + fname_len + extra_len

    # Read rest of header + filename + extra
    rest_header = resp.raw.read(fname_len + extra_len)

    # Now stream compressed data after header_total_size
    def generate():
        # yield local file header + filename + extra
        yield content + rest_header
        # yield compressed data
        remaining = comp_size
        while remaining > 0:
            chunk_size = min(8192, remaining)
            chunk = resp.raw.read(chunk_size)
            if not chunk:
                break
            yield chunk
            remaining -= len(chunk)

    # Send as file attachment with original filename
    return Response(generate(),
                    headers={
                        'Content-Disposition': f'attachment; filename="{filename}"',
                        'Content-Type': 'application/octet-stream'
                    })

from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/")
def home():
    return jsonify({"message": "PicknFetch backend is running."})

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
