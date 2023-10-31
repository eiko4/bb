"""An addon using the abbreviated scripting syntax."""
import sys
import json
import base64
from mitmproxy.net.http.http1.assemble import assemble_request, assemble_response


def response(flow):
    #flow.request.headers["myheader"] = "value"
    #print(flow.request.raw_content);
    if flow.request.host == "www.bbc.com" and flow.request.raw_content is not None:
     response = flow.response.copy()  # type: ignore
     response.decode(strict=False)
     raw_resp = myassemble_response(response);
     raw_req = assemble_request(flow.request);
     sys.stdout.write('\n');
     sys.stdout.write('------------delemiter------------');
     sys.stdout.write('\n');
     sys.stdout.flush();
     sys.stdout.write(raw_req.decode('utf-8', errors='replace'));
     sys.stdout.write('\n');
     sys.stdout.write('------------delemiter------------');
     sys.stdout.write('\n');
     sys.stdout.flush();
     sys.stdout.write(raw_resp.decode('utf-8', errors='replace'));
     sys.stdout.write('\n');
     sys.stdout.flush();


def myassemble_response(response):
    if response.data.content is None:
        raise ValueError("Cannot assemble flow with missing content")
    head = assemble_response_head(response)
    body = b"".join(
        myassemble_body(
            response.data.headers, [response.data.content], response.data.trailers
        )
    )
    return head + body
    
    
def myassemble_body(headers, body_chunks, trailers):
    if "chunked" in headers.get("transfer-encoding", "").lower():
        for chunk in body_chunks:
            if chunk:
                yield b"%s" % chunk
        if trailers:
            yield b"%s" % trailers
        else:
            yield b"\r\n\r\n"
    else:
        if trailers:
            raise ValueError(
                "Sending HTTP/1.1 trailer headers requires transfer-encoding: chunked"
            )
        for chunk in body_chunks:
            yield chunk
 
def assemble_response_head(response):
    first_line = _assemble_response_line(response.data)
    headers = _assemble_response_headers(response.data)
    return b"%s\r\n%s\r\n" % (first_line, headers)
    
    
    
def _assemble_response_line(response_data):
    return b"%s %d %s" % (
        response_data.http_version,
        response_data.status_code,
        response_data.reason,
    )
    
def _assemble_response_headers(response):
    return bytes(response.headers)
