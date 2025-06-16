from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import requests
import io
import struct
import os

app = Flask(__name__)
CORS(app)

# Helper to parse central directory entries from ZIP EOCD remote fetch
def parse_central_directory(data):
    files = []
    signature = b'\x50\x4b\x01\x02'
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

def get_eocd_range(total_size):
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
    try:
        head_resp = requests.head(url, headers=headers, allow_redirects=True, timeout=10)
        total_size = int(head_resp.headers.get('Content-Length', 0))
    except:
        total_size = 0

    # Fallback: try GET with Range to extract content length if HEAD fails
    if total_size == 0:
        try:
            headers['Range'] = 'bytes=0-1'
            test_resp = requests.get(url, headers=headers, stream=True, timeout=10)
            if test_resp.status_code in [200, 206]:
                content_range = test_resp.headers.get('Content-Range', '')
                if '/' in content_range:
                    total_size = int(content_range.split('/')[-1])
        except:
            return jsonify({'error': 'Failed to get content length'}), 400

    if total_size == 0:
        return jsonify({'error': 'Failed to get content length'}), 400

    # Step 2: Download EOCD from end of file
    start, end = get_eocd_range(total_size)
    headers['Range'] = f'bytes={start}-{end}'
    range_resp = requests.get(url, headers=headers)
    if range_resp.status_code not in [200, 206]:
        return jsonify({'error': 'Failed to download EOCD range'}), 400
    data_bytes = range_resp.content

    # Step 3: Find EOCD signature
    eocd_signature = b'\x50\x4b\x05\x06'
    eocd_pos = data_bytes.rfind(eocd_signature)
    if eocd_pos == -1:
        return jsonify({'error': 'EOCD not found in ZIP file'}), 400

    cd_size = struct.unpack('<I', data_bytes[eocd_pos+12:eocd_pos+16])[0]
    cd_offset = struct.unpack('<I', data_bytes[eocd_pos+16:eocd_pos+20])[0]

    # Step 4: Download Central Directory
    cd_start = cd_offset
    cd_end = cd_offset + cd_size - 1
    headers['Range'] = f'bytes={cd_start}-{cd_end}'
    cd_resp = requests.get(url, headers=headers)
    if cd_resp.status_code not in [200, 206]:
        return jsonify({'error': 'Failed to download central directory'}), 400
    cd_data = cd_resp.content

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

    if not all([url, filename, offset, comp_size]):
        return jsonify({'error': 'Missing required parameters'}), 400

    headers = {}
    if cookies:
        headers['Cookie'] = cookies
    if user_agent:
        headers['User-Agent'] = user_agent

    range_start = offset
    range_end = offset + comp_size + 100
    headers['Range'] = f'bytes={range_start}-{range_end}'
    resp = requests.get(url, headers=headers, stream=True)
    if resp.status_code not in [200, 206]:
        return jsonify({'error': 'Failed to download file data'}), 400

    content = resp.raw.read(30)
    if content[0:4] != b'\x50\x4b\x03\x04':
        return jsonify({'error': 'Invalid local file header'}), 400

    fname_len = struct.unpack('<H', content[26:28])[0]
    extra_len = struct.unpack('<H', content[28:30])[0]
    header_total_size = 30 + fname_len + extra_len
    rest_header = resp.raw.read(fname_len + extra_len)

    def generate():
        yield content + rest_header
        remaining = comp_size
        while remaining > 0:
            chunk_size = min(8192, remaining)
            chunk = resp.raw.read(chunk_size)
            if not chunk:
                break
            yield chunk
            remaining -= len(chunk)

    return Response(generate(), headers={
        'Content-Disposition': f'attachment; filename="{filename}"',
        'Content-Type': 'application/octet-stream'
    })

@app.route("/")
def home():
    return jsonify({"message": "PicknFetch backend is running."})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
